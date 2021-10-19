// hw2_csce612_dns.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#pragma comment(lib, "ws2_32.lib")
char* fix_recvBuf;
int recv_size;
char* reverseIP(char* host) {
    vector<string> rev_ip(4); //4-byte IP
    bool cont = true;
    char* curPos = host;
    int i = 3;
    while (cont) {
        int wordSize = 0;
        if (strchr(curPos, '.') == NULL) { //end of host
            wordSize = strlen(curPos);
            cont = false;
        }
        else wordSize = strchr(curPos, '.') - curPos;
        char* word = (char*)malloc(wordSize);
        memcpy(word, curPos, wordSize);
        word[wordSize] = '\0';
        string str(word, word + wordSize);
        rev_ip[i] = str;
        curPos = curPos + wordSize + 1; //+1: skip over dot
        i--;
    }
    string rstr = "";
    for (int c = 0; c < rev_ip.size(); c++) {
        rstr = rstr + rev_ip[c] + ".";
    }
    rstr += "in-addr.arpa";
    char* rev_host = new char[rstr.length() + 1];
    strcpy(rev_host, rstr.c_str());
    return rev_host;
}
int getOffset(char* resp) {
    int curPos = 0;
    int off = 0;
    char* buf = resp;
    if ((unsigned char)buf[curPos] >= 0xC0) {
        // compressed; so jump
        // computing the jump offset
        off = (((unsigned char)buf[curPos] & 0x3F) << 8) + (unsigned char)buf[curPos + 1];
        if (off > 0 && off < 12) {
            printf("++\tinvalid record: jump into fixed header\n");
            exit(EXIT_FAILURE);
        }
        if (buf + 1 - fix_recvBuf > recv_size + 1) {
            printf("++\tinvalid record: truncated jump offset\n");
            exit(EXIT_FAILURE);
        }
        if (off > recv_size) {
            printf("++\tinvalid record: jump beyond packet boundary\n");
            exit(EXIT_FAILURE);
        }
    }
    else {
        // uncompressed, read next word
        off = 0;
    }
    return off;
}
int printHost(char* recvBuf, int off) {
    //print host
    printf("\t");
    char* curPos = recvBuf + off;
    if ((unsigned char)curPos[0] >= 0xc0)
    {
        printf("++\tinvalid record: jump loop\n");
        exit(EXIT_FAILURE);
    }
    int total_size = 0;
    while (true) {
        int size = curPos[0];
        total_size += size;
        char* word = (char*)malloc(size);
        curPos = curPos + 1;
        memcpy(word, curPos, size);
        word[size] = '\0'; //null-terminate
        printf("%s", word);
        curPos = curPos + size;
        if (curPos[0] == 0) {
            printf(" ");
            curPos = curPos + 1;
            total_size += 2;
            break;
        }
        else {
            printf(".");
            total_size++;
        }
    }
    return total_size;
}
void parseAnswer(char* resp, FixedDNSheader* fdh, char* recvBuf, int recvBytes) {
    int loop = 0;

    for (int i = 0; i < htons(fdh->answers); i++) {
        if (resp - recvBuf >= recvBytes)
        {
            printf("++\tinvalid section: not enough records\n");
            return;
        }

        //get offset (for compressed or uncompressed)
        int off = getOffset(resp);
        //print host
        int host_size = printHost(recvBuf, off);
        //print other answers
        if (off > 0) {
            resp = resp + 2;
        }
        DNSanswerHdr* dah = (DNSanswerHdr*)(resp);
        resp = resp + sizeof(DNSanswerHdr);

        if ((int)htons(dah->ansType) == DNS_A)
        {
            char saddr[16];
            sprintf(saddr, "%d.%d.%d.%d", (unsigned char)resp[0], (unsigned char)resp[1], (unsigned char)resp[2], (unsigned char)resp[3]);
            printf("%s", saddr);
            printf(" TTL = %d\n", (16 * 16 * (int)htons(dah->ttl1)) + ((int)htons(dah->ttl2)));
            resp = resp + 4;

            continue;
        }

    }

}
char* parseQuestion(char* resp) {
    int pos = 0;
    printf("\t");
    while (true) {
        int wordSize = resp[pos];
        pos++;
        char* word = (char*)malloc(wordSize);
        memcpy(word, &resp[pos], wordSize);
        word[wordSize] = '\0'; //null-terminate
        printf("%s", word);
        pos += wordSize;
        if (resp[pos] == NULL) {
            break;
        }
        printf(".");
    }
    resp = resp + pos + 1;
    QueryHeader* rqh = (QueryHeader*)resp;
    printf(" type %d class %d\n", htons(rqh->qType), htons(rqh->qClass));
    resp = resp + sizeof(QueryHeader);
    return resp;
}
void makeDNSquestion(char* buf, char* host) {
    //set query question
    buf = buf + sizeof(FixedDNSheader);
    int i = 0;
    char* curPos = host;
    bool cont = true;
    while (cont) { //split host, append to buf
        int wordSize = 0;
        if (strchr(curPos, '.') == NULL) {
            wordSize = strlen(curPos);
            cont = false;
        }
        else wordSize = strchr(curPos, '.') - curPos;
        buf[i] = wordSize; i++;
        memcpy(buf + i, curPos, wordSize);
        i += wordSize;
        curPos = curPos + wordSize + 1;
    }
    buf[i] = 0; // last word NULL-terminated
}

int main(char* argc, char* argv[])
{
    char* host = argv[1];
    char* serverIP = argv[2];

    printf("Lookup\t\t: %s\n", host);
    /*Get query type*/
    int type;
    DWORD ip = inet_addr(host);
    if (ip == INADDR_NONE) { //if not ip
        //type A
        type = DNS_A;
    }
    else {
        //type-ptr
        type = DNS_PTR;
        //reverse IP
        host = reverseIP(host);
    }

    /*Make packet to send*/
    //char host[] = "www.google.com";
    int pkt_size = strlen(host) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);
    char* packet = new char[pkt_size];
    // fixed field initialization
    FixedDNSheader* dh = (FixedDNSheader*)packet;
    QueryHeader* qh = (QueryHeader*)(packet + pkt_size - sizeof(QueryHeader));
    dh->ID = htons(1); //txid
    dh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);;
    dh->questions = htons(1);
    dh->answers = htons(0);
    dh->authority = htons(0);
    dh->additional = htons(0);
    if (type == DNS_A)
        qh->qType = htons(DNS_A);
    else qh->qType = htons(DNS_PTR);
    qh->qClass = htons(DNS_INET);

    printf("Query\t\t: %s, type %d, TXID %#x\n", host, htons(qh->qType), htons(dh->ID));
    printf("Server\t\t: %s\n", serverIP);
    printf("********************************\n");
    // fill in the question
    makeDNSquestion(packet, host);

    /*Bind Socket*/
    WSADATA wsaData;

    //Initialize WinSock; once per program run
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        printf("WSAStartup error %s\n", WSAGetLastError());
        WSACleanup();
        return 0;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Error on %s: %s\n", __FUNCTION__, WSAGetLastError());
        WSACleanup();
        return 0;
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        // handle errors 
        printf("Error on %s: %s\n", __FUNCTION__, WSAGetLastError());
        WSACleanup();
        return 0;
    }

    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(serverIP);; // server¡¯s IP
    remote.sin_port = htons(53); // DNS port on server

    /*Send and receive*/
    int count = 0;
    while (count++ < MAX_ATTEMPTS)
    {
        printf("Attempt %d with %d bytes... \n", count - 1, pkt_size);
        // Send packet to the server
        if (sendto(sock, packet, pkt_size, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
            printf("Error on %s: %d\n", __FUNCTION__, WSAGetLastError());
            WSACleanup();
            return 0;
        }
        // Receive packet from the server
        fd_set fd;
        timeval tp;
        tp.tv_sec = 10; tp.tv_usec = 0;
        FD_ZERO(&fd); // clear the set
        FD_SET(sock, &fd); // add your socket to the set
        int available = select(0, &fd, NULL, NULL, &tp);

        char recvBuf[MAX_DNS_LEN];
        struct sockaddr_in response;
        int size = sizeof(response);

        if (available > 0)
        {
            int recv = recvfrom(sock, recvBuf, MAX_DNS_LEN, 0, (struct sockaddr*)&response, &size);
            fix_recvBuf = recvBuf;
            recv_size = recv;
            if (recv == SOCKET_ERROR) {
                printf("Error on %s: %d\n", __FUNCTION__, WSAGetLastError());
                delete packet;
                return 0;
            }

            if (response.sin_addr.s_addr != remote.sin_addr.s_addr || response.sin_port != remote.sin_port)
            {
                printf("Error on %s: Bogus Reply\n", __FUNCTION__);
                delete packet;
                return 0;
            }

            /*Get DNS header*/
            FixedDNSheader* rfdh = (FixedDNSheader*)recvBuf;
            // read fdh->ID and other fields
            printf("  TXID 0x%04x flags 0x%04x questions %d answers %d authority %d additional %d\n", htons(rfdh->ID), 
                htons(rfdh->flags), (int)htons(rfdh->questions), (int)htons(rfdh->answers),
                (int)htons(rfdh->authority), (int)htons(rfdh->additional));
            if (htons(rfdh->ID) != htons(dh->ID)) {
                printf("\t++ invalid reply: TXID mismatch, sent 0x%04x, received 0x%04x\n", htons(dh->ID), htons(rfdh->ID));
                return 0;
            }
            int rcode = htons(rfdh->flags) & 0x000f;
            if (rcode == 0) {
                printf("  succeeded with Rcode = %d\n", rcode);
            }
            else
            {
                printf("  failed with Rcode = %d\n", rcode);
                return 0;
            }

            char* resp = recvBuf + sizeof(FixedDNSheader);
            /*Parse Question*/
            printf("  ------------ [questions] ------------\n");
            resp = parseQuestion(resp);// +1;
            /*Get DNS answer header*/
            printf("  ------------ [answers] ------------\n");
            parseAnswer(resp, rfdh, recvBuf, recv);
            
            // read dah->len and other fields 

            return 0;
        }
        else if (available == 0) { //Timeout
            //printf("error: Timeout\n");
            printf("Error: timeout\n");
            return 0;
        }
        else { //SOCKET_ERROR
            printf("Socket error: %d\n", WSAGetLastError());
            return 0;
        }
    }

    return 0;
}