/*
 * netfilter.c
 * (C) 2018, all rights reserved,
 *
 * This file is part of WinDivert.
 *
 * WinDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * WinDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * DESCRIPTION:
 * This is a simple traffic filter/firewall using WinDivert.
 *
 * usage: netfilter.exe windivert-filter [priority]
 *
 * Any traffic that matches the windivert-filter will be blocked using one of
 * the following methods:
 * - TCP: send a TCP RST to the packet's source.
 * - UDP: send a ICMP(v6) "destination unreachable" to the packet's source.
 * - ICMP/ICMPv6: Drop the packet.
 *
 * This program is similar to Linux's iptables with the "-j REJECT" target.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WINDIVERT_KERNEL

#include "windivert.h"

/*
#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)
#define htons(x)            WinDivertHelperHtons(x)
#define htonl(x)            WinDivertHelperHtonl(x)
*/

#define MAXBUF              0xFFFF
#define INET6_ADDRSTRLEN    45
#define IPPROTO_ICMPV6      58

/*
 * Pre-fabricated packets.
 */
typedef struct
{
    WINDIVERT_IPHDR ip;
    WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

typedef struct
{
    WINDIVERT_IPV6HDR ipv6;
    WINDIVERT_TCPHDR tcp;
} TCPV6PACKET, *PTCPV6PACKET;

typedef struct
{
    WINDIVERT_IPHDR ip;
    WINDIVERT_ICMPHDR icmp;
    UINT8 data[];
} ICMPPACKET, *PICMPPACKET;

typedef struct
{
    WINDIVERT_IPV6HDR ipv6;
    WINDIVERT_ICMPV6HDR icmpv6;
    UINT8 data[];
} ICMPV6PACKET, *PICMPV6PACKET;

typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_UDPHDR udp;
} UDPIPV4PACKET, *PUDPIPV4PACKET;

/*
 * Prototypes.
 */
static void PacketIpInit(PWINDIVERT_IPHDR packet);
static void PacketIpTcpInit(PTCPPACKET packet);
static void PacketIpIcmpInit(PICMPPACKET packet);
static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet);
static void PacketIpv6TcpInit(PTCPV6PACKET packet);
static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet);

#include "winsock.h"

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
	HANDLE handle, console;
	UINT i = 0;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr, swap_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT32 src_addr[4], dst_addr[4];
	char src_str[INET6_ADDRSTRLEN + 1], dst_str[INET6_ADDRSTRLEN + 1];
	UINT payload_len;
	const char *err_str;

	TCPPACKET reset0;
	PTCPPACKET reset = &reset0;
	UINT8 dnr0[sizeof(ICMPPACKET) + 0x0F * sizeof(UINT32) + 8 + 1];
	PICMPPACKET dnr = (PICMPPACKET)dnr0;

	TCPV6PACKET resetv6_0;
	PTCPV6PACKET resetv6 = &resetv6_0;
	UINT8 dnrv6_0[sizeof(ICMPV6PACKET) + sizeof(WINDIVERT_IPV6HDR) +
		sizeof(WINDIVERT_TCPHDR)];
	PICMPV6PACKET dnrv6 = (PICMPV6PACKET)dnrv6_0;

	// Check arguments.

	char reflectAddress[32];
	int verbose = FALSE;
	int port = -1;

	while (++i < argc)
	{
		if (!_stricmp(argv[i], "-reflect_address"))
		{
			strcpy_s(reflectAddress, sizeof(reflectAddress) - 1, argv[++i]);
		}
		else if (!_stricmp(argv[i], "-verbose"))
		{
			verbose = TRUE;
		}
		else if (!_stricmp(argv[i], "-shield"))
		{
			port = atoi(argv[++i]);
		}
	}

	if (strlen(reflectAddress) < 8)
	{
		fprintf(stderr, "need to specify a reflect address\n");
		exit(EXIT_FAILURE);
	}
	if (port < 0)
	{
	}

	char filterString[256];

	sprintf_s(filterString, sizeof(filterString) - 1, "outbound and ip.DstAddr == %s",
		reflectAddress);

	char work_string[256];

	if (port > 0)
	{
		sprintf_s(work_string, sizeof(work_string) - 1, "or inbound and tcp.DstPort == %i", port);
		sprintf_s(filterString, sizeof(filterString) - 1, "%s %s", filterString, work_string);
	}

	printf("NetReflect (WinDivert): reflecting packets with filter %s (%s)\n", filterString,
						verbose ? "with tracing on" : "quietly");

	handle = WinDivertOpen(filterString, WINDIVERT_LAYER_NETWORK, 0, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER )  
			/* &&
			!WinDivertHelperCompileFilter(filterString, WINDIVERT_LAYER_NETWORK,
				NULL, 0, &err_str, NULL)) */
		{
			fprintf(stderr, "error: invalid filter \"%s\"\n", filterString);
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main loop:
	int readPackets = 0;
	int sentPackets = 0;
	int readErrors = 0;
	int sendErrors = 0;
	int sent_len = 0;
	__int64 readBytes = 0;
	__int64 sentBytes = 0;

	while (TRUE)
	{
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr,
			&packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			readErrors++;

			continue;
		}
		else
		{
			readPackets++;
			readBytes += packet_len;
		}
		
		if (verbose)
		{
			// Print info about the matching packet.
			WinDivertHelperParsePacket(packet, packet_len, &ip_header,
				&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
				&udp_header, NULL, &payload_len);
			if (ip_header == NULL && ipv6_header == NULL)
			{
				continue;
			}

			if (ip_header != NULL)
			{
				struct in_addr Src, Dst;
				Src.S_un.S_addr = ip_header->SrcAddr;
				Dst.S_un.S_addr = ip_header->DstAddr;

				char *SrcAddr, *DstAddr;
				SrcAddr = inet_ntoa(Src);
				DstAddr = inet_ntoa(Dst);

				printf("ip.SrcAddr=%s ip.DstAddr=%s ", SrcAddr, DstAddr);
			}

			if (udp_header != NULL)
			{
				printf("udp.SrcPort=%u udp.DstPort=%u, %u bytes\n",
					ntohs(udp_header->SrcPort), ntohs(udp_header->DstPort),
					ntohs(udp_header->Length));

			}
		}


		// swap send and receive address
		memcpy(&send_addr, &recv_addr, sizeof(send_addr));
		send_addr.Direction = !recv_addr.Direction;

		// this could be more efficient, but for now we want to trace it easily.		
		PUDPIPV4PACKET pRecv_header = packet;
		UDPIPV4PACKET send_header;

		// copy to the send header
		memcpy(&send_header, pRecv_header, sizeof(UDPIPV4PACKET));
		// swap the source and destination addresses.
		send_header.ip.DstAddr = pRecv_header->ip.SrcAddr;
		send_header.ip.SrcAddr = pRecv_header->ip.DstAddr;

		// copy the temp header back into the packet
		memcpy(pRecv_header, &send_header, sizeof(UDPIPV4PACKET));

		int cc_count = WinDivertHelperCalcChecksums((PVOID)packet, packet_len, &send_addr, 0);

		int sent_len = -1;
		int stat = WinDivertSend(handle, (PVOID)packet, packet_len,
			&send_addr, &sent_len);

		if (!stat)
		{
			fprintf(stderr, "error sending packet for reflection (return:%d last error:%d)\n  ", stat,
				GetLastError());
			sendErrors++;
		}
		else
		{
			if (verbose)
			{
				printf("reflect: %d bytes\n", sent_len);
			}

			sentPackets++;
			sentBytes += sent_len;
		}

		if (!(readPackets % 1000))
		{
			sprintf_s(work_string, sizeof(work_string) - 1, "%i packets read, %I64d total bytes",
								readPackets, readBytes);

			printf( "%s, %i packets reflected, %I64d total bytes\n", work_string, sentPackets, sentBytes);
		}
	}
}


#if 0

            if packet.is_outbound:
                (packet.src_addr, packet.dst_addr) = \
                    (packet.dst_addr, packet.src_addr)
                packet.direction = pydivert.Direction.INBOUND
                logger.debug('Reflecting packet:\n%r', packet)
                wd.send(packet)

		    else:
                logger.debug('Dropping packet
					reflect(args.reflect_address, args.shield, args.priority)
					except PermissionError as e :
				sys.exit(f'Caught PermissionError: are you running this program '
					f'with Administrator privileges?\n{e!r}')* /

					*/

#endif


#if 0
    // Initialize all packets.
    PacketIpTcpInit(reset);
    reset->tcp.Rst = 1;
    reset->tcp.Ack = 1;
    PacketIpIcmpInit(dnr);
    dnr->icmp.Type = 3;         // Destination not reachable.
    dnr->icmp.Code = 3;         // Port not reachable.
    PacketIpv6TcpInit(resetv6);
    resetv6->tcp.Rst = 1;
    resetv6->tcp.Ack = 1;
    PacketIpv6Icmpv6Init(dnrv6);
    dnrv6->ipv6.Length = htons(sizeof(WINDIVERT_ICMPV6HDR) + 4 +
        sizeof(WINDIVERT_IPV6HDR) + sizeof(WINDIVERT_TCPHDR));
    dnrv6->icmpv6.Type = 1;     // Destination not reachable.
    dnrv6->icmpv6.Code = 4;     // Port not reachable.

    // Get console for pretty colors.
    console = GetStdHandle(STD_OUTPUT_HANDLE);

    // Divert traffic matching the filter:
    handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, priority, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER &&
            !WinDivertHelperCompileFilter(argv[1], WINDIVERT_LAYER_NETWORK,
                NULL, 0, &err_str, NULL))
        {
            fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Main loop:
    while (TRUE)
    {
        // Read a matching packet.
        if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr,
                &packet_len))
        {
            fprintf(stderr, "warning: failed to read packet\n");
            continue;
        }
       
        // Print info about the matching packet.
        WinDivertHelperParsePacket(packet, packet_len, &ip_header,
            &ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
            &udp_header, NULL, &payload_len);
        if (ip_header == NULL && ipv6_header == NULL)
        {
            continue;
        }

        // Dump packet info: 
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        fputs("BLOCK ", stdout);
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        if (ip_header != NULL)
        {
            WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr),
                src_str, sizeof(src_str));
            WinDivertHelperFormatIPv4Address(ntohl(ip_header->DstAddr),
                dst_str, sizeof(dst_str));
        }
        if (ipv6_header != NULL)
        {
            WinDivertHelperNtohIpv6Address(ipv6_header->SrcAddr, src_addr);
            WinDivertHelperNtohIpv6Address(ipv6_header->DstAddr, dst_addr);
            WinDivertHelperFormatIPv6Address(src_addr, src_str,
                sizeof(src_str));
            WinDivertHelperFormatIPv6Address(dst_addr, dst_str,
                sizeof(dst_str));
        }

        printf("ip.SrcAddr=%s ip.DstAddr=%s ", src_str, dst_str);
        if (icmp_header != NULL)
        {
            printf("icmp.Type=%u icmp.Code=%u ",
                icmp_header->Type, icmp_header->Code);
            // Simply drop ICMP
        }
        if (icmpv6_header != NULL)
        {
            printf("icmpv6.Type=%u icmpv6.Code=%u ",
                icmpv6_header->Type, icmpv6_header->Code);
            // Simply drop ICMPv6
        }

        if (tcp_header != NULL)
        {
            printf("tcp.SrcPort=%u tcp.DstPort=%u tcp.Flags=",
                ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort));
            if (tcp_header->Fin)
            {
                fputs("[FIN]", stdout);
            }
            if (tcp_header->Rst)
            {
                fputs("[RST]", stdout);
            }
            if (tcp_header->Urg)
            {
                fputs("[URG]", stdout);
            }
            if (tcp_header->Syn)
            {
                fputs("[SYN]", stdout);
            }
            if (tcp_header->Psh)
            {
                fputs("[PSH]", stdout);
            }
            if (tcp_header->Ack)
            {
                fputs("[ACK]", stdout);
            }
            putchar(' ');


            if (ip_header != NULL && !tcp_header->Rst && !tcp_header->Fin)
            {
                reset->ip.SrcAddr = ip_header->DstAddr;
                reset->ip.DstAddr = ip_header->SrcAddr;
                reset->tcp.SrcPort = tcp_header->DstPort;
                reset->tcp.DstPort = tcp_header->SrcPort;
                reset->tcp.SeqNum = 
                    (tcp_header->Ack? tcp_header->AckNum: 0);
                reset->tcp.AckNum =
                    (tcp_header->Syn?
                        htonl(ntohl(tcp_header->SeqNum) + 1):
                        htonl(ntohl(tcp_header->SeqNum) + payload_len));

                memcpy(&send_addr, &recv_addr, sizeof(send_addr));
                send_addr.Direction = !recv_addr.Direction;
                WinDivertHelperCalcChecksums((PVOID)reset, sizeof(TCPPACKET),
                    &send_addr, 0);
                if (!WinDivertSend(handle, (PVOID)reset, sizeof(TCPPACKET),
                        &send_addr, NULL))
                {
                    fprintf(stderr, "warning: failed to send TCP reset (%d)\n",
                        GetLastError());
                }
            }

            if (ipv6_header != NULL && !tcp_header->Rst && !tcp_header->Fin)
            {
                memcpy(resetv6->ipv6.SrcAddr, ipv6_header->DstAddr,
                    sizeof(resetv6->ipv6.SrcAddr));
                memcpy(resetv6->ipv6.DstAddr, ipv6_header->SrcAddr,
                    sizeof(resetv6->ipv6.DstAddr));
                resetv6->tcp.SrcPort = tcp_header->DstPort;
                resetv6->tcp.DstPort = tcp_header->SrcPort;
                resetv6->tcp.SeqNum =
                    (tcp_header->Ack? tcp_header->AckNum: 0);
                resetv6->tcp.AckNum =
                    (tcp_header->Syn?
                        htonl(ntohl(tcp_header->SeqNum) + 1):
                        htonl(ntohl(tcp_header->SeqNum) + payload_len));

                memcpy(&send_addr, &recv_addr, sizeof(send_addr));
                send_addr.Direction = !recv_addr.Direction;
                WinDivertHelperCalcChecksums((PVOID)resetv6,
                    sizeof(TCPV6PACKET), &send_addr, 0);
                if (!WinDivertSend(handle, (PVOID)resetv6, sizeof(TCPV6PACKET),
                        &send_addr, NULL))
                {
                    fprintf(stderr, "warning: failed to send TCP (IPV6) "
                        "reset (%d)\n", GetLastError());
                }
            }
        }

        if (udp_header != NULL)
        {
            printf("udp.SrcPort=%u udp.DstPort=%u ",
                ntohs(udp_header->SrcPort), ntohs(udp_header->DstPort));
        
            if (ip_header != NULL)
            {
                UINT icmp_length = ip_header->HdrLength*sizeof(UINT32) + 8;
                memcpy(dnr->data, ip_header, icmp_length);
                icmp_length += sizeof(ICMPPACKET);
                dnr->ip.Length = htons((UINT16)icmp_length);
                dnr->ip.SrcAddr = ip_header->DstAddr;
                dnr->ip.DstAddr = ip_header->SrcAddr;
                
                memcpy(&send_addr, &recv_addr, sizeof(send_addr));
                send_addr.Direction = !recv_addr.Direction;
                WinDivertHelperCalcChecksums((PVOID)dnr, icmp_length,
                    &send_addr, 0);
                if (!WinDivertSend(handle, (PVOID)dnr, icmp_length, &send_addr,
                    NULL))
                {
                    fprintf(stderr, "warning: failed to send ICMP message "
                        "(%d)\n", GetLastError());
                }
            }
        
            if (ipv6_header != NULL)
            {
                UINT icmpv6_length = sizeof(WINDIVERT_IPV6HDR) +
                    sizeof(WINDIVERT_TCPHDR);
                memcpy(dnrv6->data, ipv6_header, icmpv6_length);
                icmpv6_length += sizeof(ICMPV6PACKET);
                memcpy(dnrv6->ipv6.SrcAddr, ipv6_header->DstAddr,
                    sizeof(dnrv6->ipv6.SrcAddr));
                memcpy(dnrv6->ipv6.DstAddr, ipv6_header->SrcAddr,
                    sizeof(dnrv6->ipv6.DstAddr));
                
                memcpy(&send_addr, &recv_addr, sizeof(send_addr));
                send_addr.Direction = !recv_addr.Direction;
                WinDivertHelperCalcChecksums((PVOID)dnrv6, icmpv6_length,
                    &send_addr, 0);
                if (!WinDivertSend(handle, (PVOID)dnrv6, icmpv6_length,
                        &send_addr, NULL))
                {
                    fprintf(stderr, "warning: failed to send ICMPv6 message "
                        "(%d)\n", GetLastError());
                }
            }
        }
        putchar('\n');

#endif


/*
 * Initialize a PACKET.
 */
static void PacketIpInit(PWINDIVERT_IPHDR packet)
{
    memset(packet, 0, sizeof(WINDIVERT_IPHDR));
    packet->Version = 4;
    packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
    packet->Id = ntohs(0xDEAD);
    packet->TTL = 64;
}

/*
 * Initialize a TCPPACKET.
 */
static void PacketIpTcpInit(PTCPPACKET packet)
{
    memset(packet, 0, sizeof(TCPPACKET));
    PacketIpInit(&packet->ip);
    packet->ip.Length = htons(sizeof(TCPPACKET));
    packet->ip.Protocol = IPPROTO_TCP;
    packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
 * Initialize an ICMPPACKET.
 */
static void PacketIpIcmpInit(PICMPPACKET packet)
{
    memset(packet, 0, sizeof(ICMPPACKET));
    PacketIpInit(&packet->ip);
    packet->ip.Protocol = IPPROTO_ICMP;
}

/*
 * Initialize a PACKETV6.
 */
static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet)
{
    memset(packet, 0, sizeof(WINDIVERT_IPV6HDR));
    packet->Version = 6;
    packet->HopLimit = 64;
}

/*
 * Initialize a TCPV6PACKET.
 */
static void PacketIpv6TcpInit(PTCPV6PACKET packet)
{
    memset(packet, 0, sizeof(TCPV6PACKET));
    PacketIpv6Init(&packet->ipv6);
    packet->ipv6.Length = htons(sizeof(WINDIVERT_TCPHDR));
    packet->ipv6.NextHdr = IPPROTO_TCP;
    packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
 * Initialize an ICMP PACKET.
 */
static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet)
{
    memset(packet, 0, sizeof(ICMPV6PACKET));
    PacketIpv6Init(&packet->ipv6);
    packet->ipv6.NextHdr = IPPROTO_ICMPV6;
}

