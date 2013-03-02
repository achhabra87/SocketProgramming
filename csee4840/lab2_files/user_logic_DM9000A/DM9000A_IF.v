module DM9000A_IF(	//	HOST Side
					iDATA,oDATA,iCMD,
					iRD_N,iWR_N,
					iCS_N,iRST_N,
					oINT,
					//	DM9000A Side
					ENET_DATA,ENET_CMD,
					ENET_RD_N,ENET_WR_N,
					ENET_CS_N,ENET_RST_N,
					ENET_INT
					);
//	HOST Side
input	[15:0]	iDATA;
input			iCMD;
input			iRD_N;
input			iWR_N;
input			iCS_N;
input			iRST_N;
output	[15:0]	oDATA;
output			oINT;
//	DM9000A Side
inout	[15:0]	ENET_DATA;
output			ENET_CMD;
output			ENET_RD_N;
output			ENET_WR_N;
output			ENET_CS_N;
output			ENET_RST_N;
input			ENET_INT;

assign	ENET_DATA	=	ENET_WR_N	?	16'hzzzz	:	iDATA	;
assign	oDATA		=	ENET_DATA	;

assign	ENET_CMD 	=	iCMD;
assign	ENET_RD_N 	=	iRD_N;
assign	ENET_WR_N	=	iWR_N;
assign	ENET_CS_N	=	iCS_N;
assign	ENET_RST_N	=	iRST_N;
assign	oINT		=	ENET_INT;

endmodule



