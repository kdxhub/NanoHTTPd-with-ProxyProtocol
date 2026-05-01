package org.nanohttpd.protocols;

/*
 * #%L
 * NanoHttpd-Core
 * %%
 * Copyright (C) 2012 - 2026 nanohttpd
 * %%
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the nanohttpd nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * #L%
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Decode a InputStream with Proxy Protocol.
 * 
 * @author kdxiaoyi
 */
public class ProxyProtocol {

    /**
     * @see {@link https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt}
     */
    public static class PROXY_PROTOCOL_SUPPORT {

        public static final String V1 = "v1";

        public static final String V2 = "v2";

        public static final String AUTO = "auto";

        public static final String NONE = "none";
    }

    public final String realIp;

    public final int realPort;

    public final boolean available;

    public final InnerData rawData;

    public final String detectedVersion;

    // V2 protocol constants
    public static final byte[] V2_SIGNATURE = {
        0x0D,
        0x0A,
        0x0D,
        0x0A,
        0x00,
        0x0D,
        0x0A,
        0x51,
        0x55,
        0x49,
        0x54,
        0x0A
    };

    public static final int V2_SIGNATURE_LENGTH = 12;

    public static final int V2_HEADER_MIN_LENGTH = 16;

    // v2 address family / protocol constants
    public static final byte AF_UNSPEC = 0x00;

    public static final byte AF_INET = 0x10;

    public static final byte AF_INET6 = 0x20;

    public static final byte AF_UNIX = 0x30;

    public static final byte PROTO_STREAM = 0x01;

    // v1 token
    public static final String V1_PREFIX = "PROXY";

    /**
     * Inner class holding the consumed raw proxy header bytes.
     */
    public static class InnerData {

        public final byte[] bytes;

        public InnerData(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public String toString() {
            return new String(bytes, StandardCharsets.US_ASCII);
        }
    }

    /**
     * Try and get details.
     * 
     * @param in
     *            <b>The Proxy Protocol part will be consumed, </b>otherwise it
     *            doesn't support MARK .
     * @param version
     *            See {@link ProxyProtocol.PROXY_PROTOCOL_SUPPORT}
     * @throws IllegalArgumentException
     *             When param [version] is wrong.
     * @throws IllegalArgumentException
     *             When param [in] doesn't support MARK.
     */
    public ProxyProtocol(InputStream in, String version) throws IllegalArgumentException {
        if (version == null) {
            throw new IllegalArgumentException("[version] cannot be null");
        }

        boolean parseSuccess = false;
        String detected = null;
        String rip = null;
        int rport = -1;
        InnerData raw = null;

        try {
            switch (version) {
                case PROXY_PROTOCOL_SUPPORT.NONE:
                    // 版本为 none 时抛出异常
                    throw new IllegalArgumentException("Proxy protocol version is set to NONE, no parsing should be attempted.");

                case PROXY_PROTOCOL_SUPPORT.V1:
                    // 仅尝试 v1
                    ProxyProtocolV1Result v1Result = parseV1(in);
                    if (v1Result != null) {
                        parseSuccess = true;
                        detected = PROXY_PROTOCOL_SUPPORT.V1;
                        rip = v1Result.ip;
                        rport = v1Result.port;
                        raw = new InnerData(v1Result.rawBytes);
                    }
                    break;

                case PROXY_PROTOCOL_SUPPORT.V2:
                    // 仅尝试 v2
                    ProxyProtocolV2Result v2Result = parseV2(in);
                    if (v2Result != null) {
                        parseSuccess = true;
                        detected = PROXY_PROTOCOL_SUPPORT.V2;
                        rip = v2Result.ip;
                        rport = v2Result.port;
                        raw = new InnerData(v2Result.rawBytes);
                    }
                    break;

                case PROXY_PROTOCOL_SUPPORT.AUTO:
                    // 同时尝试 v1 和 v2：先 v2 再 v1
                    ProxyProtocolV2Result v2AutoResult = parseV2(in);
                    if (v2AutoResult != null) {
                        parseSuccess = true;
                        detected = PROXY_PROTOCOL_SUPPORT.V2;
                        rip = v2AutoResult.ip;
                        rport = v2AutoResult.port;
                        raw = new InnerData(v2AutoResult.rawBytes);
                    } else {
                        // v2 失败，尝试 v1
                        ProxyProtocolV1Result v1AutoResult = parseV1(in);
                        if (v1AutoResult != null) {
                            parseSuccess = true;
                            detected = PROXY_PROTOCOL_SUPPORT.V1;
                            rip = v1AutoResult.ip;
                            rport = v1AutoResult.port;
                            raw = new InnerData(v1AutoResult.rawBytes);
                        }
                    }
                    break;

                default:
                    throw new IllegalArgumentException("Unsupported proxy protocol version: " + version);
            }
        } catch (IllegalArgumentException eIA) {
            throw eIA;
        } catch (IOException e) {
            // IO 异常视为解析失败
            parseSuccess = false;
        }

        // 如果解析失败，回退流并将数据置为 null
        if (!parseSuccess) {
            this.available = false;
            this.realIp = null;
            this.realPort = 0;
            this.rawData = null;
            this.detectedVersion = null;
        } else {
            this.available = true;
            this.realIp = rip;
            this.realPort = rport;
            this.rawData = raw;
            this.detectedVersion = detected;
        }
    }

    // ---------- V1 解析 ----------

    private ProxyProtocolV1Result parseV1(InputStream in) throws IOException {
        if (!in.markSupported()) {
            // mark 不支持则直接返回，不破坏流
            throw new IllegalArgumentException("Unsupported InputStream.");
        }
        // 标记当前位置，预留足够长度（v1 单行最长通常 107 字节左右）
        in.mark(512);

        try {
            ByteArrayOutputStream headerBuf = new ByteArrayOutputStream();
            int b;
            while ((b = in.read()) != -1) {
                headerBuf.write(b);
                // v1 以 \n 结尾
                if (b == '\n') {
                    break;
                }
                // 简单截断保护
                if (headerBuf.size() > 512) {
                    return null;
                }
            }

            byte[] rawBytes = headerBuf.toByteArray();
            String line = new String(rawBytes, StandardCharsets.US_ASCII).trim();

            // 必须以 "PROXY" 开头
            if (!line.startsWith(V1_PREFIX)) {
                in.reset();
                return null;
            }

            String[] parts = line.split(" ");
            // 格式：PROXY <INET> <src> <dst> <sport> <dport>
            if (parts.length < 6 || !parts[0].equals(V1_PREFIX)) {
                in.reset();
                return null;
            }

            String inet = parts[1];
            String srcIp = parts[2];
            String dstIp = parts[3];
            String srcPort = parts[4];
            String dstPort = parts[5];

            // UNKNOWN 类型处理
            if ("UNKNOWN".equals(inet)) {
                // 返回 null 表示没有有效地址
                in.reset();
                return null;
            }

            // 简单校验 ip 格式
            if (!isValidIp(srcIp)) {
                in.reset();
                return null;
            }

            int port = Integer.parseInt(srcPort);
            // 已成功解析，保留 rawData，流已消耗
            return new ProxyProtocolV1Result(srcIp, port, rawBytes);

        } catch (Exception e) {
            // 任何异常都回退流
            in.reset();
            return null;
        }
    }

    // ---------- V2 解析 ----------

    private ProxyProtocolV2Result parseV2(InputStream in) throws IOException {
        if (!in.markSupported()) {
            throw new IllegalArgumentException("Unsupported InputStream.");
        }
        in.mark(V2_SIGNATURE_LENGTH + 256); // 预留足够长度用于完整头部

        try {
            // 1. 读取并验证 12 字节签名
            byte[] signature = new byte[V2_SIGNATURE_LENGTH];
            int readBytes = in.read(signature);
            if (readBytes < V2_SIGNATURE_LENGTH || !Arrays.equals(signature, V2_SIGNATURE)) {
                in.reset();
                return null;
            }

            // 2. 读取 ver_cmd 字节
            int verCmd = in.read();
            if (verCmd == -1) {
                in.reset();
                return null;
            }
            int version = (verCmd >> 4) & 0x0F;
            if (version != 2) {
                in.reset();
                return null;
            }

            // 3. 读取地址族 / 传输协议字节
            int familyProto = in.read();
            if (familyProto == -1) {
                in.reset();
                return null;
            }
            int addressFamily = familyProto & 0xF0;
            int protocol = familyProto & 0x0F;

            // 4. 读取地址长度（2 字节，网络字节序）
            byte[] lenBytes = new byte[2];
            readBytes = in.read(lenBytes);
            if (readBytes < 2) {
                in.reset();
                return null;
            }
            int addressLength = ((lenBytes[0] & 0xFF) << 8) | (lenBytes[1] & 0xFF);

            // 5. 读取地址块
            byte[] addressBlock = new byte[addressLength];
            readBytes = in.read(addressBlock);
            if (readBytes < addressLength) {
                in.reset();
                return null;
            }

            // 6. 构造完整原始数据
            byte[] fullRaw = new byte[V2_SIGNATURE_LENGTH + 2 + 2 + addressLength];
            System.arraycopy(signature, 0, fullRaw, 0, V2_SIGNATURE_LENGTH);
            fullRaw[V2_SIGNATURE_LENGTH] = (byte) verCmd;
            fullRaw[V2_SIGNATURE_LENGTH + 1] = (byte) familyProto;
            fullRaw[V2_SIGNATURE_LENGTH + 2] = lenBytes[0];
            fullRaw[V2_SIGNATURE_LENGTH + 3] = lenBytes[1];
            System.arraycopy(addressBlock, 0, fullRaw, V2_SIGNATURE_LENGTH + 4, addressLength);

            // 7. 提取源 IP 和端口
            ByteBuffer addrBuffer = ByteBuffer.wrap(addressBlock);

            String srcIp;
            int srcPort;
            switch (addressFamily) {
                case AF_INET: // IPv4 (TCP or UDP)
                    byte[] srcIpv4 = new byte[4];
                    addrBuffer.get(srcIpv4);
                    byte[] dstIpv4 = new byte[4];
                    addrBuffer.get(dstIpv4);
                    srcPort = addrBuffer.getShort() & 0xFFFF;
                    int dstPort = addrBuffer.getShort() & 0xFFFF;
                    srcIp = InetAddress.getByAddress(srcIpv4).getHostAddress();
                    break;

                case AF_INET6: // IPv6
                    byte[] srcIpv6 = new byte[16];
                    addrBuffer.get(srcIpv6);
                    byte[] dstIpv6 = new byte[16];
                    addrBuffer.get(dstIpv6);
                    srcPort = addrBuffer.getShort() & 0xFFFF;
                    // 跳过 dstPort
                    addrBuffer.getShort();
                    srcIp = InetAddress.getByAddress(srcIpv6).getHostAddress();
                    break;

                case AF_UNIX: // Unix socket
                    // 128 字节源地址 + 128 字节目标地址，无端口
                    byte[] srcUnix = new byte[128];
                    addrBuffer.get(srcUnix);
                    byte[] dstUnix = new byte[128];
                    addrBuffer.get(dstUnix);
                    srcIp = "localhost"; // Unix socket 视为本地
                    srcPort = 0;
                    break;

                case AF_UNSPEC: // 未指定
                default:
                    srcIp = null;
                    srcPort = -1;
                    break;
            }

            return new ProxyProtocolV2Result(srcIp, srcPort, fullRaw);

        } catch (Exception e) {
            in.reset();
            return null;
        }
    }

    // ---------- 辅助方法 ----------

    private boolean isValidIp(String ip) {
        try {
            InetAddress.getByName(ip);
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    // ---------- 结果容器 ----------

    private static class ProxyProtocolV1Result {

        final String ip;

        final int port;

        final byte[] rawBytes;

        ProxyProtocolV1Result(String ip, int port, byte[] rawBytes) {
            this.ip = ip;
            this.port = port;
            this.rawBytes = rawBytes;
        }
    }

    private static class ProxyProtocolV2Result {

        final String ip;

        final int port;

        final byte[] rawBytes;

        ProxyProtocolV2Result(String ip, int port, byte[] rawBytes) {
            this.ip = ip;
            this.port = port;
            this.rawBytes = rawBytes;
        }
    }
}
