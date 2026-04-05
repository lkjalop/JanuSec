"""Helper to create a deterministic pcap fixture containing a ClientHello.
Run this as a script to produce `clienthello_canonical.pcap` in the same folder.
"""
import struct
import os

PCAP_GLOBAL_HDR = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def make_clienthello_bytes():
    # Construct a minimal TLSv1.2 ClientHello-like blob that the parser can pick up.
    # Build handshake: record header (type=22), version=0x0303, length to follow
    # Handshake header: type=1 (ClientHello), length (3 bytes)
    # Minimal client hello: legacy_version (0x0303), random(32), session id len=0, cipher suites len=2, one cipher, comp len=1, ext len=... 
    ciphers = b'\x00\x2f'  # TLS_RSA_WITH_AES_128_CBC_SHA
    sig_algs_ext = b'\x00\x0d'  # signature_algorithms
    # For simplicity build an SNI extension with example.com
    hostname = b'example.com'
    sni_list = b'\x00' + struct.pack('>H', len(hostname)) + hostname
    sni_ext = b'\x00\x00' + struct.pack('>H', 2 + len(sni_list)) + struct.pack('>H', len(sni_list)) + sni_list
    # supported_groups extension (0x000a) minimal with one group 0x0017
    groups_ext = b'\x00\x0a' + struct.pack('>H', 2 + 2) + struct.pack('>H', 2) + b'\x00\x17'
    # signature_algorithms ext: two-byte list
    sigs = b'\x00\x02\x04\x03'  # arbitrary
    sigs_ext = b'\x00\x0d' + struct.pack('>H', len(sigs)) + sigs
    extensions = sni_ext + groups_ext + sigs_ext
    # compute ext len
    ext_len = struct.pack('>H', len(extensions))
    legacy_version = b'\x03\x03'
    random = b'\x00' * 32
    session_id = b'\x00'
    cipher_len = struct.pack('>H', len(ciphers))
    comp = b'\x01\x00'
    # assemble handshake body
    body = legacy_version + random + session_id + cipher_len + ciphers + comp + ext_len + extensions
    hs_type = b'\x01'
    hs_len = len(body)
    hs_len3 = hs_len.to_bytes(3, 'big')
    handshake = hs_type + hs_len3 + body
    rec_len = len(handshake).to_bytes(2, 'big')
    record = b'\x16\x03\x03' + rec_len + handshake
    return record

def write_pcap(path):
    pkt = make_clienthello_bytes()
    # minimal packet header with current ts
    import time
    ts = int(time.time())
    ts_usec = int((time.time() - ts) * 1e6)
    incl_len = len(pkt)
    orig_len = len(pkt)
    pkt_hdr = struct.pack('<IIII', ts, ts_usec, incl_len, orig_len)
    with open(path, 'wb') as fh:
        fh.write(PCAP_GLOBAL_HDR)
        fh.write(pkt_hdr)
        fh.write(pkt)

if __name__ == '__main__':
    p = os.path.join(os.path.dirname(__file__), 'clienthello_canonical.pcap')
    write_pcap(p)
    print('Wrote', p)
