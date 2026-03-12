"""
File malware scanner — three-layer detection:

  Layer 1  VirusTotal hash lookup        (70+ AV engines, instant for known files)
  Layer 2  LightGBM on real PE features  (lief-based static analysis)
  Layer 3  oletools macro analysis        (Office documents)
           Script heuristics             (.js/.vbs/.ps1/.bat)
           Entropy + byte analysis       (all file types)
"""

import os
import math
import hashlib
import collections
import re
import time
import requests
import numpy as np
import joblib
from flask import current_app

from app import db
from app.models.scans import FileScan
from app.utils.file_handler import (
    save_uploaded_file, get_file_hash,
    get_file_size, get_file_type, format_file_size
)
from app.utils.validators import calculate_threat_level

# ── Model loading ──────────────────────────────────────────────────────────────
_MODEL_DIR   = os.path.join(os.path.dirname(__file__), '..', '..', 'ml_models')
_file_model  = None
_file_scaler = None
_models_ok   = False

def _load_models():
    global _file_model, _file_scaler, _models_ok
    if _models_ok:
        return True
    try:
        _file_model  = joblib.load(os.path.join(_MODEL_DIR, 'file_malware_model.pkl'))
        _file_scaler = joblib.load(os.path.join(_MODEL_DIR, 'file_malware_scaler.pkl'))
        _models_ok   = True
        print('[file_scanner] LightGBM model loaded OK')
        return True
    except Exception as e:
        print(f'[file_scanner] Could not load models: {e}')
        return False


# ── Constants ──────────────────────────────────────────────────────────────────
# Only APIs that are highly specific to malware and rarely used in legitimate code.
# Excluded: LoadLibrary, GetProcAddress, CreateProcess, IsDebuggerPresent, OpenProcess
# — these are used legitimately by countless applications (plugin loaders, launchers,
#   debugger-aware tools, security software, etc.).
SUSPICIOUS_APIS = {
    'VirtualAllocEx',            # remote process memory allocation
    'WriteProcessMemory',        # write to another process
    'ReadProcessMemory',         # read from another process
    'CreateRemoteThread',        # inject thread into another process
    'CreateRemoteThreadEx',
    'NtCreateThreadEx',          # undocumented NT thread injection
    'NtUnmapViewOfSection',      # process hollowing
    'ZwUnmapViewOfSection',
    'SetWindowsHookEx',          # keylogger / hooking
    'GetAsyncKeyState',          # keylogger
    'URLDownloadToFile',         # download payload (rare in legit apps)
    'WinExec',                   # deprecated exec, used by malware
}

STANDARD_SECTIONS = {'.text', '.data', '.rdata', '.rsrc', '.reloc', '.pdata',
                     '.bss', '.idata', '.edata', '.tls', '.debug', '.fptable'}

PACKED_NAMES = {'upx0', 'upx1', 'upx2', '.upx', '.packed', 'aspack', '.adata',
                '.themida', '.vmp0', '.vmp1', 'petite', '.nsp0', '.nsp1'}

SCRIPT_EXTS  = {'.js', '.vbs', '.vbe', '.ps1', '.bat', '.cmd', '.sh', '.hta'}
OFFICE_EXTS  = {'.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm',
                '.ppt', '.pptx', '.pptm', '.odt', '.ods', '.odp'}
PE_EXTS      = {'.exe', '.dll', '.scr', '.sys', '.com', '.drv', '.ocx', '.cpl'}


# ── Entropy helpers ────────────────────────────────────────────────────────────
def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = collections.Counter(data)
    total = len(data)
    return -sum((v / total) * math.log2(v / total) for v in c.values() if v)


def _file_entropy(filepath: str, max_bytes: int = 1_048_576) -> float:
    try:
        with open(filepath, 'rb') as f:
            return _entropy(f.read(max_bytes))
    except Exception:
        return 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  Layer 1 — VirusTotal hash lookup
# ══════════════════════════════════════════════════════════════════════════════

def _virustotal_lookup(sha256: str) -> dict | None:
    """
    Query VirusTotal v3 for the given SHA256 hash.
    Returns a dict with 'malicious', 'total_engines', 'verdict', 'av_names'
    or None if unavailable / not found.
    """
    api_key = current_app.config.get('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        return None

    try:
        url  = f'https://www.virustotal.com/api/v3/files/{sha256}'
        hdrs = {'x-apikey': api_key, 'Accept': 'application/json'}
        resp = requests.get(url, headers=hdrs, timeout=10)

        if resp.status_code == 404:
            return {'found': False}

        if resp.status_code == 200:
            attrs  = resp.json()['data']['attributes']
            stats  = attrs.get('last_analysis_stats', {})
            names  = [
                eng for eng, res in attrs.get('last_analysis_results', {}).items()
                if res.get('category') in ('malicious', 'suspicious')
            ]
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) or 1
            return {
                'found'       : True,
                'malicious'   : malicious,
                'suspicious'  : suspicious,
                'total_engines': total,
                'verdict'     : 'malicious' if malicious > 2 else (
                                'suspicious' if (malicious + suspicious) > 0 else 'clean'),
                'av_names'    : names[:5],
            }
    except Exception as e:
        print(f'[VT] Error: {e}')
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  Layer 2 — PE feature extraction (lief)
# ══════════════════════════════════════════════════════════════════════════════

def _extract_pe_features(filepath: str, file_size: int) -> np.ndarray:
    """
    Extract the 30-feature vector matching train_file_malware_model.py.
    Returns all-zeros for non-PE or parse failures.
    """
    f = np.zeros(30)
    f[22] = 0   # is_pe starts false

    try:
        import lief
        binary = lief.parse(filepath)
        if binary is None or not isinstance(binary, lief.PE.Binary):
            return f

        f[22] = 1  # is_pe

        sections = list(binary.sections)
        f[0]  = len(sections)

        entropies = [_entropy(bytes(s.content)) for s in sections if s.content]
        if entropies:
            f[2] = float(np.mean(entropies))
            f[3] = float(np.max(entropies))
            f[4] = sum(1 for e in entropies if e > 7.0)

        # .text section entropy
        for s in sections:
            if s.name.lower().strip('\x00') in ('.text', 'code', '.code'):
                f[1] = _entropy(bytes(s.content))
                break
        if f[1] == 0 and entropies:
            f[1] = entropies[0]

        # Imports
        imports = list(binary.imports) if binary.imports else []
        f[5]  = len(imports)
        all_funcs = [fn.name for lib in imports for fn in list(lib.entries)]
        f[6]  = len(all_funcs)
        f[7]  = sum(1 for fn in all_funcs if fn in SUSPICIOUS_APIS)

        f[8]  = 1.0 if binary.has_debug else 0.0
        f[9]  = 1.0 if binary.has_tls   else 0.0

        # Overlay: data after last section
        try:
            overlay = binary.overlay
            f[10] = 1.0 if overlay and len(overlay) > 512 else 0.0
        except Exception:
            f[10] = 0.0

        f[11] = 1.0 if binary.header.characteristics & 0x2000 else 0.0  # IMAGE_FILE_DLL

        # Virtual vs raw size ratio
        total_virtual = sum(s.virtual_size for s in sections) or 1
        total_raw     = sum(s.size         for s in sections) or 1
        f[12] = min(total_virtual / total_raw, 20.0)

        # Unusual section names
        f[13] = sum(1 for s in sections
                    if s.name.lower().strip('\x00') not in STANDARD_SECTIONS)

        f[14] = file_size / (1024 * 1000)       # norm to MB
        f[15] = 1.0 if file_size < 10_240 else 0.0
        f[16] = 1.0 if binary.has_resources else 0.0

        # Checksum
        try:
            stored   = binary.optional_header.checksum
            computed = binary.compute_checksum()
            f[17] = 0.0 if stored == 0 or stored == computed else 1.0
        except Exception:
            f[17] = 0.0

        # Timestamp
        ts = binary.header.time_date_stamps
        f[18] = 1.0 if ts == 0 else 0.0
        f[19] = 1.0 if ts > 1_800_000_000 else 0.0   # beyond ~2027

        # Exports
        try:
            exports = list(binary.exported_functions)
            f[20] = len(exports)
        except Exception:
            f[20] = 0.0

        # Packed section names
        f[21] = 1.0 if any(
            s.name.lower().strip('\x00') in PACKED_NAMES for s in sections
        ) else 0.0

    except Exception as e:
        print(f'[lief] parse error: {e}')

    # Universal features
    f[23] = _file_entropy(filepath)
    f[24] = 1.0 if file_size > 10_485_760 else 0.0
    return f


# ══════════════════════════════════════════════════════════════════════════════
#  Layer 3a — oletools Office macro analysis
# ══════════════════════════════════════════════════════════════════════════════

def _analyze_office_file(filepath: str, ext: str) -> dict:
    """
    Run oletools VBA_Parser on Office documents.
    Returns a dict with macro risk info.
    """
    result = {
        'has_macros'   : False,
        'auto_exec'    : False,
        'suspicious_kw': False,
        'macro_score'  : 0,
        'risk_factors' : [],
    }
    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, \
            TYPE_Word2003_XML, TYPE_MHTML

        vba = VBA_Parser(filepath)
        if not vba.detect_vba_macros():
            return result

        result['has_macros'] = True
        result['risk_factors'].append('Contains VBA macros')
        result['macro_score'] += 30

        analysis = vba.analyze_macros()
        for kw_type, keyword, description in analysis:
            kw_type_up = kw_type.upper()
            if kw_type_up == 'AUTOEXEC':
                result['auto_exec'] = True
                result['risk_factors'].append(f'Auto-executing macro: {keyword}')
                result['macro_score'] += 30
            elif kw_type_up in ('SUSPICIOUS', 'OBFUSCATION'):
                result['suspicious_kw'] = True
                result['risk_factors'].append(f'Suspicious macro keyword: {keyword}')
                result['macro_score'] = min(result['macro_score'] + 15, 100)
            elif kw_type_up == 'IOC':
                result['risk_factors'].append(f'IOC in macro: {description}')
                result['macro_score'] = min(result['macro_score'] + 20, 100)

    except ImportError:
        result['risk_factors'].append('oletools not available')
    except Exception as e:
        print(f'[oletools] {e}')

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  Layer 3b — Script heuristics
# ══════════════════════════════════════════════════════════════════════════════

_OBFUSCATION_RE = re.compile(
    r'fromCharCode|String\.fromChar|unescape\(|atob\(|btoa\(|eval\s*\(|'
    r'base64|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', re.IGNORECASE
)
_DOWNLOAD_EXEC_RE = re.compile(
    r'URLDownloadToFile|Invoke-Expression|IEX\s*\(|DownloadString|'
    r'DownloadFile|WebClient|Start-Process|WScript\.Shell|'
    r'powershell\s+-[eE]|cmd\.exe\s*/[cC]', re.IGNORECASE
)
_PROCESS_RE = re.compile(
    r'CreateObject|Shell\s*\(|WScript|cscript|mshta|regsvr32|'
    r'certutil\s+-decode', re.IGNORECASE
)


def _analyze_script(filepath: str) -> dict:
    result = {
        'has_obfuscation'  : False,
        'has_download_exec': False,
        'has_process_create': False,
        'entropy'          : 0.0,
        'risk_factors'     : [],
        'score'            : 0,
    }
    try:
        with open(filepath, 'rb') as fh:
            raw = fh.read(65_536)
        result['entropy'] = _entropy(raw)
        try:
            text = raw.decode('utf-8', errors='replace')
        except Exception:
            text = ''

        if _OBFUSCATION_RE.search(text):
            result['has_obfuscation']   = True
            result['risk_factors'].append('Obfuscation techniques detected')
            result['score'] += 25

        if _DOWNLOAD_EXEC_RE.search(text):
            result['has_download_exec'] = True
            result['risk_factors'].append('Download-and-execute pattern detected')
            result['score'] += 35

        if _PROCESS_RE.search(text):
            result['has_process_create'] = True
            result['risk_factors'].append('Process creation / shell execution detected')
            result['score'] += 20

        if result['entropy'] > 5.5:
            result['risk_factors'].append(f'High script entropy ({result["entropy"]:.2f}) — possible obfuscation')
            result['score'] += 15

    except Exception as e:
        print(f'[script_analysis] {e}')
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  Feature vector assembly (non-PE files)
# ══════════════════════════════════════════════════════════════════════════════

def _build_feature_vector(filepath: str, file_size: int, ext: str,
                           office_result: dict, script_result: dict) -> np.ndarray:
    """Build the 30-element feature vector for non-PE files."""
    f = np.zeros(30)
    f[23] = _file_entropy(filepath)
    f[24] = 1.0 if file_size > 10_485_760 else 0.0
    f[14] = file_size / (1024 * 1000)

    if ext in SCRIPT_EXTS:
        f[25] = 1.0
        f[27] = 1.0 if script_result['has_obfuscation']   else 0.0
        f[28] = 1.0 if script_result['has_process_create'] else 0.0
        f[29] = 1.0 if script_result['has_download_exec']  else 0.0

    if ext in OFFICE_EXTS:
        f[26] = 1.0
        f[28] = 1.0 if office_result['has_macros']    else 0.0
        f[27] = 1.0 if office_result['suspicious_kw'] else 0.0
        f[29] = 1.0 if office_result['auto_exec']     else 0.0

    return f


# ══════════════════════════════════════════════════════════════════════════════
#  ML prediction
# ══════════════════════════════════════════════════════════════════════════════

def _ml_predict(feature_vec: np.ndarray) -> tuple[bool, float]:
    """Returns (is_malicious, confidence 0-1)."""
    if not _load_models():
        return False, 0.5
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            scaled = _file_scaler.transform(feature_vec.reshape(1, -1))
            prob   = _file_model.predict_proba(scaled)[0][1]
        return prob >= 0.5, float(prob)
    except Exception as e:
        print(f'[ML] predict error: {e}')
        return False, 0.5


# ══════════════════════════════════════════════════════════════════════════════
#  Heuristic fallback (no lief available)
# ══════════════════════════════════════════════════════════════════════════════

def _heuristic_fallback(filepath: str, file_size: int, ext: str) -> dict:
    score = 0.0
    risk  = []

    if ext in {'.exe', '.dll', '.scr', '.com'}:
        score += 0.35; risk.append('Executable file type')
    elif ext in {'.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta'}:
        score += 0.30; risk.append('Script file type')

    entropy = _file_entropy(filepath)
    if entropy > 7.2:
        score += 0.30; risk.append(f'Very high entropy ({entropy:.2f}) — likely packed')
    elif entropy > 6.5:
        score += 0.15; risk.append(f'High entropy ({entropy:.2f})')

    if file_size < 10_240 and ext in PE_EXTS:
        score += 0.15; risk.append('Unusually small executable')

    is_mal = score >= 0.5
    return {
        'is_malicious'   : is_mal,
        'confidence'     : min(score if is_mal else 1 - score, 0.95),
        'malware_type'   : 'Suspicious File' if is_mal else None,
        'risk_factors'   : risk,
        'detection_source': 'heuristic',
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Malware type determination
# ══════════════════════════════════════════════════════════════════════════════

def _determine_malware_type(ext: str, feature_vec: np.ndarray,
                             office_result: dict, script_result: dict) -> str:
    if ext in OFFICE_EXTS:
        if office_result.get('auto_exec'):
            return 'Macro Malware (Auto-Executing)'
        if office_result.get('has_macros'):
            return 'Macro Malware'
        return 'Malicious Document'

    if ext in SCRIPT_EXTS:
        if script_result.get('has_download_exec'):
            return 'Dropper Script'
        if script_result.get('has_obfuscation'):
            return 'Obfuscated Script'
        return 'Malicious Script'

    # PE-based classification
    if feature_vec[4] >= 2 or feature_vec[3] >= 7.4:
        return 'Packed / Encrypted Malware'
    if feature_vec[7] >= 3:
        return 'Injector / RAT'
    if feature_vec[29] == 1:
        return 'Dropper / Downloader'
    if feature_vec[21] == 1:
        return 'Packed Malware'
    if ext in {'.exe', '.com', '.scr'}:
        return 'Executable Threat'
    if ext in {'.dll', '.sys', '.drv'}:
        return 'Malicious DLL'
    return 'Suspicious File'


# ══════════════════════════════════════════════════════════════════════════════
#  Public API
# ══════════════════════════════════════════════════════════════════════════════

def scan_file(file, user=None):
    """
    Scan an uploaded file using three-layer detection.
    Returns: dict with scan results.
    """
    try:
        file_info = save_uploaded_file(file)
        if not file_info:
            return {'success': False, 'error': 'Invalid file or file type not allowed'}

        filepath  = file_info['filepath']
        filename  = file_info['filename']
        file_hash = file_info['hash_sha256']
        file_size = file_info['size']
        file_type = file_info['type']

        _, ext = os.path.splitext(filename)
        ext = ext.lower()

        risk_factors      = []
        detection_source  = 'ml'
        vt_info           = {}
        office_result     = {}
        script_result     = {}

        # ── Layer 1: VirusTotal ──────────────────────────────────────────────
        vt = _virustotal_lookup(file_hash)
        if vt and vt.get('found'):
            vt_info = vt
            if vt['verdict'] == 'malicious':
                malware_type = 'Malware (VirusTotal)'
                mal_names    = ', '.join(vt.get('av_names', []))
                risk_factors.append(
                    f"Flagged by {vt['malicious']}/{vt['total_engines']} AV engines"
                    + (f": {mal_names}" if mal_names else '')
                )
                result = {
                    'success'          : True,
                    'filename'         : filename,
                    'file_hash'        : file_hash,
                    'file_size'        : format_file_size(file_size),
                    'file_type'        : file_type,
                    'is_malicious'     : True,
                    'threat_level'     : 'Critical',
                    'malware_type'     : malware_type,
                    'confidence_score' : min(
                        vt['malicious'] / max(vt['total_engines'], 1) * 100, 99
                    ),
                    'risk_factors'     : risk_factors,
                    'detection_source' : 'VirusTotal',
                    'vt_malicious'     : vt['malicious'],
                    'vt_total'         : vt['total_engines'],
                    'scan_id'          : None,
                }
                _save_and_cleanup(result, user, filepath, file_size, file_type)
                return result

        # ── Layer 2 + 3: Local analysis ──────────────────────────────────────
        if ext in OFFICE_EXTS:
            office_result = _analyze_office_file(filepath, ext)
            risk_factors.extend(office_result.get('risk_factors', []))

            # If oletools finds dangerous macros, trust it directly
            if office_result['macro_score'] >= 60:
                fv = _build_feature_vector(filepath, file_size, ext,
                                           office_result, {})
                is_malicious = True
                confidence   = office_result['macro_score'] / 100.0
                malware_type = _determine_malware_type(ext, fv, office_result, {})
                detection_source = 'oletools'
            else:
                fv = _build_feature_vector(filepath, file_size, ext,
                                           office_result, {})
                is_malicious, confidence = _ml_predict(fv)
                malware_type = _determine_malware_type(ext, fv, office_result, {}) \
                               if is_malicious else None

        elif ext in SCRIPT_EXTS:
            script_result = _analyze_script(filepath)
            risk_factors.extend(script_result.get('risk_factors', []))

            if script_result['score'] >= 50:
                is_malicious = True
                confidence   = min(script_result['score'] / 100.0, 0.97)
                malware_type = _determine_malware_type(ext, np.zeros(30),
                                                       {}, script_result)
                detection_source = 'heuristic'
            else:
                fv = _build_feature_vector(filepath, file_size, ext,
                                           {}, script_result)
                is_malicious, confidence = _ml_predict(fv)
                malware_type = _determine_malware_type(ext, fv, {}, script_result) \
                               if is_malicious else None

        elif ext in PE_EXTS or _is_pe(filepath):
            fv = _extract_pe_features(filepath, file_size)
            if fv[22] == 1:    # valid PE parsed by lief
                is_malicious, confidence = _ml_predict(fv)
                malware_type = _determine_malware_type(ext, fv, {}, {}) \
                               if is_malicious else None
                # Add specific risk factors from PE features
                if fv[4] >= 2:
                    risk_factors.append(f'{int(fv[4])} sections with entropy > 7.0 (packed)')
                if fv[7] >= 3:
                    risk_factors.append(f'{int(fv[7])} suspicious API calls detected')
                if fv[17]:
                    risk_factors.append('Invalid PE checksum')
                if fv[21]:
                    risk_factors.append('Packer signature detected in section names')
                if fv[10]:
                    risk_factors.append('Data overlay found after last section')
            else:
                fb = _heuristic_fallback(filepath, file_size, ext)
                is_malicious  = fb['is_malicious']
                confidence    = fb['confidence']
                malware_type  = fb['malware_type']
                risk_factors.extend(fb['risk_factors'])
                detection_source = 'heuristic'
                fv = np.zeros(30)

        else:
            # Generic file (PDF, image, archive, etc.)
            fv = np.zeros(30)
            fv[23] = _file_entropy(filepath)
            fv[24] = 1.0 if file_size > 10_485_760 else 0.0
            is_malicious, confidence = _ml_predict(fv)
            malware_type = 'Suspicious File' if is_malicious else None

        if not is_malicious:
            risk_factors = []
            malware_type  = None

        # VT supplement (not decisive, but add info)
        if vt_info.get('found') and vt_info.get('suspicious', 0) > 0:
            risk_factors.append(
                f"Flagged as suspicious by {vt_info['suspicious']} AV engine(s) on VirusTotal"
            )

        threat_level = calculate_threat_level(confidence) if is_malicious else 'Clean'

        result = {
            'success'          : True,
            'filename'         : filename,
            'file_hash'        : file_hash,
            'file_size'        : format_file_size(file_size),
            'file_type'        : file_type,
            'is_malicious'     : is_malicious,
            'threat_level'     : threat_level,
            'malware_type'     : malware_type,
            'confidence_score' : round(confidence * 100, 2),
            'risk_factors'     : risk_factors,
            'detection_source' : detection_source,
            'scan_id'          : None,
        }

        _save_and_cleanup(result, user, filepath, file_size, file_type)
        return result

    except Exception as e:
        return {'success': False, 'error': str(e)}


def _is_pe(filepath: str) -> bool:
    """Quick PE magic check."""
    try:
        with open(filepath, 'rb') as f:
            return f.read(2) == b'MZ'
    except Exception:
        return False


def _save_and_cleanup(result: dict, user, filepath: str,
                      file_size: int, file_type: str):
    if user:
        try:
            scan_record = FileScan(
                user_id          = user.id,
                filename         = result['filename'],
                file_hash        = result['file_hash'],
                file_size        = file_size,
                file_type        = file_type,
                is_malicious     = result['is_malicious'],
                threat_level     = result['threat_level'],
                malware_type     = result.get('malware_type'),
                confidence_score = result['confidence_score'] / 100.0,
                rf_prediction    = result.get('detection_source', 'N/A'),
                svm_prediction   = 'N/A',
                dt_prediction    = 'N/A',
            )
            db.session.add(scan_record)
            db.session.commit()
            result['scan_id'] = scan_record.id
        except Exception as e:
            print(f'[db] save error: {e}')

    try:
        os.remove(filepath)
    except Exception:
        pass


def scan_multiple_files(files, user=None):
    return [scan_file(f, user) for f in files]
