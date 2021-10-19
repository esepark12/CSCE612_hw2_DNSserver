#pragma pack(push,1) // sets struct padding/alignment to 1 byte

class QueryHeader {
public:
	u_short qType;
	u_short qClass;
};

class FixedDNSheader {
public:
	u_short ID;
	u_short flags;
	u_short questions;
	u_short answers;
	u_short authority;
	u_short additional;
};

class DNSanswerHdr {
public:
	u_short ansType;
	u_short ansClass;
	u_short ttl1;
	u_short ttl2;
	u_short len;
};

#pragma pack(pop) // restores old packing