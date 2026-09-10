# -*- coding: utf-8 -*-
"""
IEC 61850-9-2 SV 报文 LSB 隐蔽信道：嵌入 + 提取（完整可运行版）
原理：seqData 中每个 INT32 采样值仅改末 4 bit，所有 TLV 长度不变，
      在原始字节上原位修改；多 MU 混合 pcap 先按 (源MAC, svID) 分流。
两种嵌入模式：
  repeat —— 每一帧独立嵌入完整字符串（帧内头: 魔数8b + 字节数8b），
            任意一帧即可解出，全部报文帧均为载体；
  spread —— 字符串跨帧铺开嵌入一次（流头: 魔数16b + 字节数16b），
            只占用流内前几帧。
适配实测报文：savPdu 标签 0x60/0x61 均兼容；seqData 为 N×(值4B+品质4B)，
通道数 N 由每帧 seqData 实际长度现场计算，不写死。
"""

import struct
from typing import List, Tuple

# ============================================================
# 第 1 部分：BER-TLV 基础解析
# ============================================================
def _read_length(buf: bytes, off: int) -> Tuple[int, int]:
    """读取 BER 长度字段，返回 (内容长度, 内容起始偏移)"""
    first = buf[off]
    if first < 0x80:                       # 短格式
        return first, off + 1
    n = first & 0x7F                       # 长格式 (0x81/0x82...)
    return int.from_bytes(buf[off+1:off+1+n], 'big'), off + 1 + n

def _read_tlv(buf: bytes, off: int) -> Tuple[int, int, int]:
    """返回 (tag, 内容偏移, 内容长度)"""
    length, content_off = _read_length(buf, off + 1)
    return buf[off], content_off, length

def _skip_tlv(buf: bytes, off: int) -> int:
    """跳过整个 TLV，返回下一个 TLV 偏移"""
    _, c_off, c_len = _read_tlv(buf, off)
    return c_off + c_len

# ============================================================
# 第 2 部分：SV 报文结构定位
# ============================================================
def find_apdu_offset(frame: bytes) -> int:
    """定位以太网帧中 SV APDU 起点（支持可选 802.1Q VLAN 标签）"""
    eth_type = int.from_bytes(frame[12:14], 'big')
    off = 14
    if eth_type == 0x8100:                 # VLAN 标签
        eth_type = int.from_bytes(frame[16:18], 'big')
        off = 18
    if eth_type != 0x88BA:
        raise ValueError(f"非 SV 报文，EtherType=0x{eth_type:04X}")
    return off + 8                         # APPID(2)+Length(2)+Reserved(4)

def find_seqdata_spans(frame: bytes) -> List[Tuple[int, int]]:
    """定位 APDU 内所有 ASDU 的 seqData(0x87) 内容区，返回 [(偏移, 字节数)]"""
    spans = []
    tag, c_off, c_len = _read_tlv(frame, find_apdu_offset(frame))
    if tag not in (0x60, 0x61):            # savPdu，实测报文用 0x60
        raise ValueError(f"期望 savPdu 标签 0x60/0x61，实际 0x{tag:02X}")
    end, off = c_off + c_len, c_off
    while off < end:                       # savPdu 内字段
        t, co, cl = _read_tlv(frame, off)
        if t == 0xA2:                      # seqASDU [2]
            a_off, a_end = co, co + cl
            while a_off < a_end:           # 遍历每个 ASDU(0x30)
                at, aco, acl = _read_tlv(frame, a_off)
                if at == 0x30:
                    f_off, f_end = aco, aco + acl
                    while f_off < f_end:   # 遍历 ASDU 内字段
                        ft, fco, fcl = _read_tlv(frame, f_off)
                        if ft == 0x87:     # seqData [7]
                            spans.append((fco, fcl))
                        f_off = _skip_tlv(frame, f_off)
                a_off = _skip_tlv(frame, a_off)
        off = _skip_tlv(frame, off)
    return spans

def get_svid(frame: bytes) -> str:
    """取第一个 ASDU 的 svID（须进入 ASDU 内部，避开 savPdu 的 noASDU 0x80）"""
    _, c_off, c_len = _read_tlv(frame, find_apdu_offset(frame))
    off, end = c_off, c_off + c_len
    while off < end:
        t, co, _ = _read_tlv(frame, off)
        if t == 0xA2:
            _, aco, _ = _read_tlv(frame, co)      # 第一个 ASDU
            ft, fco, fcl = _read_tlv(frame, aco)  # ASDU 首字段即 svID
            if ft == 0x80:
                return frame[fco:fco+fcl].decode('ascii', 'replace')
        off = _skip_tlv(frame, off)
    return ''

def get_src_mac(frame: bytes) -> str:
    return ':'.join(f'{b:02X}' for b in frame[6:12])

# ============================================================
# 第 3 部分：比特流工具
# ============================================================
def bytes_to_bits(data: bytes) -> List[int]:
    """字节串 → 比特列表（每字节 MSB 在前）"""
    return [(b >> (7 - i)) & 1 for b in data for i in range(8)]

def bits_to_bytes(bits: List[int]) -> bytes:
    """比特列表 → 字节串（尾部不足 8 bit 补 0）"""
    bits = list(bits)
    while len(bits) % 8:
        bits.append(0)
    return bytes(sum(bits[i+k] << (7-k) for k in range(8))
                 for i in range(0, len(bits), 8))

# ============================================================
# 第 4 部分：核心 —— 单帧 INT32 采样值末 4 位嵌入 / 提取
# ============================================================
def embed_bits_in_frame(frame: bytes, bits: List[int], pos: int = 0
                        ) -> Tuple[bytes, int]:
    """
    把 bits[pos:] 依次嵌入帧内各 ASDU 的 seqData。
    每个 INT32 采样值承载 4 bit：只改该值最低字节的低 4 位，
    品质字(quality)保持不变。返回 (新帧字节, 已消耗比特下标)。
    通道数由 seqData 实际长度 /8 现场得出，随报文配置自适应。
    """
    buf = bytearray(frame)
    for data_off, data_len in find_seqdata_spans(frame):
        n_ch = data_len // 8                     # 每通道 值4B+品质4B
        for ch in range(n_ch):
            if pos + 4 > len(bits):
                return bytes(buf), pos
            nibble = 0
            for k in range(4):                   # 先到的 bit 放 nibble 高位
                nibble = (nibble << 1) | bits[pos + k]
            pos += 4
            v_last = data_off + ch * 8 + 3       # INT32 的最低字节
            buf[v_last] = (buf[v_last] & 0xF0) | nibble
    return bytes(buf), pos

def extract_bits_from_frame(frame: bytes) -> List[int]:
    """从单帧 seqData 各 INT32 采样值低 4 位取出比特流"""
    bits = []
    for data_off, data_len in find_seqdata_spans(frame):
        for ch in range(data_len // 8):
            nibble = frame[data_off + ch * 8 + 3] & 0x0F
            bits += [(nibble >> (3 - k)) & 1 for k in range(4)]
    return bits

def frame_capacity_bits(frame: bytes) -> int:
    """单帧可承载比特数 = 通道数总和 × 4"""
    return sum((l // 8) * 4 for _, l in find_seqdata_spans(frame))

# ============================================================
# 第 5 部分：两种嵌入模式
# ============================================================
MAGIC    = 0xA5A5    # spread 模式流头魔数 16bit
PF_MAGIC = 0xA5      # repeat 模式帧内魔数 8bit

def embed_message_per_frame(frames: List[bytes], message: bytes) -> List[bytes]:
    """repeat 模式：完整字符串独立嵌入每一帧，任意一帧即可解出。
    帧内格式 = PF_MAGIC(8b) + 报文字节数(8b) + 报文比特。"""
    if len(message) > 255:
        raise ValueError("报文超过 255 字节")
    bits = bytes_to_bits(bytes([PF_MAGIC, len(message)])) + bytes_to_bits(message)
    cap = min(frame_capacity_bits(f) for f in frames)
    if len(bits) > cap:
        raise ValueError(f"单帧放不下：需 {len(bits)} bit，最小单帧容量 {cap} bit")
    out = []
    for f in frames:
        nf, pos = embed_bits_in_frame(f, bits, 0)
        assert pos == len(bits)
        out.append(nf)
    return out

def extract_message_per_frame(frames: List[bytes]) -> List:
    """repeat 模式：逐帧独立提取，返回 [(帧序号, 字符串或None)]"""
    res = []
    for i, f in enumerate(frames):
        bits = extract_bits_from_frame(f)
        if len(bits) >= 16 and bits_to_bytes(bits[:8])[0] == PF_MAGIC:
            mlen = bits_to_bytes(bits[8:16])[0]
            res.append((i, bits_to_bytes(bits[16:16+mlen*8])
                        .decode('utf-8', 'replace')))
        else:
            res.append((i, None))
    return res

def embed_message(frames: List[bytes], message: bytes) -> List[bytes]:
    """spread 模式：字符串跨帧铺开嵌入一次，流头 32bit = 魔数16b + 字节数16b"""
    bits = bytes_to_bits(struct.pack('>HH', MAGIC, len(message))) \
           + bytes_to_bits(message)
    need = sum(frame_capacity_bits(f) for f in frames)
    if len(bits) > need:
        raise ValueError(f"容量不足：需 {len(bits)} bit，目标流仅 {need} bit")
    out, pos = [], 0
    for f in frames:
        nf, pos = embed_bits_in_frame(f, bits, pos) if pos < len(bits) else (f, pos)
        out.append(nf)
    return out

def extract_message(frames: List[bytes]) -> bytes:
    """spread 模式：从连续 SV 帧流中提取隐蔽报文"""
    bits = []
    for f in frames:
        bits += extract_bits_from_frame(f)
        if len(bits) >= 32:
            magic, mlen = struct.unpack('>HH', bits_to_bytes(bits[:32]))
            if magic != MAGIC:
                raise ValueError("无嵌入（同步头未匹配）")
            if len(bits) >= 32 + mlen * 8:
                return bits_to_bytes(bits[32:32 + mlen * 8])
    raise ValueError("帧流比特数不足，报文不完整")

# ============================================================
# 第 6 部分：pcap 读写（保留原逐帧时间戳）
# ============================================================
def read_pcap(path: str):
    """读 pcap，返回 (帧字节列表, 每帧时间戳列表[(秒,微秒)])"""
    with open(path, 'rb') as f:
        data = f.read()
    endian = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    off, frames, stamps = 24, [], []
    while off < len(data):
        ts_s, ts_us, cap_len, _ = struct.unpack_from(endian + 'IIII', data, off)
        frames.append(data[off+16 : off+16+cap_len])
        stamps.append((ts_s, ts_us))
        off += 16 + cap_len
    return frames, stamps

def write_pcap(path: str, frames: List[bytes], stamps) -> None:
    """写 pcap（linktype=1 以太网），逐帧写回原时间戳"""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for fr, (ts_s, ts_us) in zip(frames, stamps):
            f.write(struct.pack('<IIII', ts_s, ts_us, len(fr), len(fr)))
            f.write(fr)

# ============================================================
# 第 7 部分：多 MU 分流 + 发送端 / 接收端
# ============================================================
def split_streams(frames: List[bytes]) -> dict:
    """按 (源MAC, svID) 分流，返回 {流标识: [帧下标,...]}，保持各流原始帧序"""
    streams = {}
    for idx, f in enumerate(frames):
        if f[12:14] == b'\x88\xba':
            streams.setdefault((get_src_mac(f), get_svid(f)), []).append(idx)
    return streams

def embed_pcap_multi(in_pcap: str, out_pcap: str, message: bytes,
                     target_svid: str = None, mode: str = 'repeat') -> None:
    """发送端：读 pcap → 分流 → 目标流每帧嵌入字符串比特串 → 按原帧序写出"""
    frames, stamps = read_pcap(in_pcap)
    streams = split_streams(frames)
    print("检测到 SV 流：")
    for (mac, svid), idxs in streams.items():
        cap = frame_capacity_bits(frames[idxs[0]])
        print(f"  svID={svid}  源MAC={mac}  帧数={len(idxs)}  单帧容量={cap}bit")
    if target_svid:                            # 指定目标流
        key = next(k for k in streams if k[1] == target_svid)
    else:                                      # 缺省取帧数最多的流
        key = max(streams, key=lambda k: len(streams[k]))
    print(f"目标流：svID={key[1]}，模式：{mode}")
    sub = [frames[i] for i in streams[key]]
    if mode == 'repeat':                       # 每帧都嵌入完整字符串
        mod = embed_message_per_frame(sub, message)
    else:                                      # 跨帧铺开，只嵌一次
        mod = embed_message(sub, message)
    out = list(frames)
    for i, nf in zip(streams[key], mod):
        out[i] = nf
    write_pcap(out_pcap, out, stamps)
    print(f"已写出：{out_pcap}")

def extract_pcap_multi(pcap_path: str, mode: str = 'repeat') -> dict:
    """接收端：读 pcap → 分流 → 逐流提取，返回 {流标识: 结果}"""
    frames, _ = read_pcap(pcap_path)
    results = {}
    for (mac, svid), idxs in split_streams(frames).items():
        sub = [frames[i] for i in idxs]
        if mode == 'repeat':
            per = extract_message_per_frame(sub)
            ok = [m for _, m in per if m is not None]
            results[(mac, svid)] = (ok[0], len(ok), len(per)) if ok else None
        else:
            try:
                results[(mac, svid)] = extract_message(sub).decode('utf-8',
                                                                   'replace')
            except ValueError:
                results[(mac, svid)] = None
    return results

# ============================================================
# 运行命令（直接写死，运行本文件即可）：
#   python3 SV隐蔽信道_嵌入提取.py
# ============================================================
if __name__ == '__main__':
    IN_PCAP  = 'ML1101_P1_brodcast_mod.pcap'  # 输入 pcap
    OUT_PCAP = 'ML1101_P1_嵌入后.pcap'         # 输出 pcap
    SECRET   = 'IED42-TRIP'              # 要隐藏的字符串
    TARGET   = 'ML1001/LLN0.smvcb0'      # 目标流 svID，None 则自动选最大流
    MODE     = 'repeat'                  # repeat=每帧都嵌入；spread=跨帧嵌一次

    # 第一步：嵌入
    embed_pcap_multi(IN_PCAP, OUT_PCAP, SECRET.encode('utf-8'), TARGET, MODE)

    # 第二步：从输出 pcap 提取验证
    print("\n逐流提取结果：")
    for (mac, svid), r in extract_pcap_multi(OUT_PCAP, MODE).items():
        if r:
            msg, ok, total = r
            print(f"  svID={svid} ({mac}): {msg}  —— {ok}/{total} 帧均携带")
        else:
            print(f"  svID={svid} ({mac}): 无嵌入")