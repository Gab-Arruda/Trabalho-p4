/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;
const bit<8> TYPE_INT = 150; //0x96;
const bit<8> TYPE_NONE = 255; //0x96;

#define MAX_HOPS 10
#define ETHERNET_SIZE 14
#define IPV4_SIZE 20

#define INT_PAI_SIZE 14
#define INT_FILHO_SIZE 37

//counter index for stats
#define PACKET_COUNTER_TOTAL 0
#define PACKET_COUNTER_TCP 1
#define PACKET_COUNTER_UDP 2


#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> sequenceNum;
    bit<32> ackNum;
    bit<4> dataOffset;
    bit<3> res;
    bit<1> ns;
    bit<1> cwr;
    bit<1> ece;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> windowSize;
    bit<16> checksum;
    bit<16> urgPtr;
}

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header int_pai_t {
    bit<32> Tamanho_Filho;
    bit<32> Quantidade_Filhos;
    bit<8>  next_header;
    bit<8>  Telemetry_Engine_Redirect;
    bit<32>  Packet_Value;
    
    /* Outros dados*/
}

//header payload_t {
//    varbit<1460> data;
//}

header int_filho_t {
    bit<32> ID_Switch;
    bit<9> Porta_Entrada;
    bit<9> Porta_Saida;
    bit<48> Timestamp;
    bit<6> padding; /* O tamanho do cabecalho em bits deve ser multiplo de 8 */
    /* Outros dados*/
    bit<32> Counter_Total;
    bit<32> Counter_TCP;
    bit<32> Counter_UDP;
    bit<32> packet_type_ingress;
    bit<32> packet_type_egress1;
    bit<32> packet_type_egress2;
}

struct metadata {
    bit<32> remaining;
    bit<1> isEndhost;
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    int_pai_t    int_pai;
//    int_filhos_t int_lista_filhos;
    int_filho_t [MAX_HOPS] int_filho;
    tcp_t        tcp;
    udp_t        udp;
//    payload_t    payload;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            TYPE_INT: parse_int_pai;
			default: accept;
		}
    }

    state parse_int_pai {
        packet.extract(hdr.int_pai);
        meta.remaining = hdr.int_pai.Quantidade_Filhos;
        transition parse_int_filho;
    }

    state parse_int_filho {
        packet.extract(hdr.int_filho.next);
        meta.remaining = meta.remaining -1;

        transition select(meta.remaining){
            0: parse_L4;
            default: parse_int_filho;
        }
    }
    
    state parse_L4{
        transition select(hdr.int_pai.next_header){
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            TYPE_NONE: accept;
            default: accept;
        }
    }

	state parse_tcp {
		packet.extract(hdr.tcp);
//		transition parse_payload;
		transition accept;
	}

	state parse_udp {
		packet.extract(hdr.udp);
//		transition parse_payload;
		transition accept;
	}

//    state parse_payload {
//        packet.extract(hdr.payload, 10);
//        transition accept;
//    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1) swid;
    register<bit<32>>(4) packet_counter;
    register<ip4Addr_t>(1) telemetryEngineAddr;


    action inc_reg(bit<32> i){
        bit<32> var_inc;
        packet_counter.read(var_inc, i);
        var_inc = var_inc + 1;
        packet_counter.write(i, var_inc);
    }

    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, bit<1> isEndhost) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.isEndhost = isEndhost;
    }

    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action add_intfilho(){

        bit<32> var_swid;
        swid.read(var_swid, 0);
        hdr.int_pai.Quantidade_Filhos = hdr.int_pai.Quantidade_Filhos + 1;

        hdr.int_filho[MAX_HOPS-1].setValid();
        hdr.int_filho[MAX_HOPS-1].ID_Switch = var_swid;
        hdr.int_filho[MAX_HOPS-1].Porta_Entrada = standard_metadata.ingress_port;
        hdr.int_filho[MAX_HOPS-1].Porta_Saida = standard_metadata.egress_spec;
        hdr.int_filho[MAX_HOPS-1].Timestamp = standard_metadata.ingress_global_timestamp;

        packet_counter.read(var_swid, PACKET_COUNTER_TOTAL);
        hdr.int_filho[MAX_HOPS-1].Counter_Total = var_swid;

        packet_counter.read(var_swid, PACKET_COUNTER_TCP);
        hdr.int_filho[MAX_HOPS-1].Counter_TCP = var_swid;

        packet_counter.read(var_swid, PACKET_COUNTER_UDP);
        hdr.int_filho[MAX_HOPS-1].Counter_UDP = var_swid;
            
        hdr.int_filho[MAX_HOPS-1].padding = 0;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_FILHO_SIZE; //25;

        hdr.int_filho[MAX_HOPS-1].packet_type_ingress = standard_metadata.instance_type;

    }

    apply {
        if (hdr.ipv4.isValid()) {

            ipv4_lpm.apply();
            if(meta.isEndhost==1 && standard_metadata.instance_type==PKT_INSTANCE_TYPE_NORMAL){
                if(hdr.int_pai.isValid() && hdr.int_pai.Telemetry_Engine_Redirect == 0){
                    clone3(CloneType.I2E, 100, {standard_metadata, meta});
                }
            }
            
            if(!hdr.int_pai.isValid()){
                //Adiciona header Pai
                hdr.int_pai.setValid();
                hdr.int_pai.Tamanho_Filho = INT_FILHO_SIZE; //verificar se existe uma forma de extrair o tamanho das structs
                hdr.int_pai.Quantidade_Filhos = 0;
                hdr.int_pai.Telemetry_Engine_Redirect = 0;
                hdr.int_pai.Packet_Value = standard_metadata.instance_type;
                //salva o protocolo que viria apos o ipv4 no next_header do pai e 
                //seta o protocol do ipv4 para int. 
                //O proximo hop vai identificar a existencia do int_pai no parser pelo IP.proto==TYPE_INT.
                hdr.int_pai.next_header = hdr.ipv4.protocol;
                hdr.ipv4.protocol= TYPE_INT;
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_PAI_SIZE; //hdr.int_pai.sizeInBytes(); //9;
            }

            if(standard_metadata.instance_type != PKT_INSTANCE_TYPE_INGRESS_RECIRC){
                inc_reg(PACKET_COUNTER_TOTAL);
                if(hdr.tcp.isValid()){
                    inc_reg(PACKET_COUNTER_TCP);
                }
                if(hdr.udp.isValid()){
                    inc_reg(PACKET_COUNTER_UDP);
                }
            }


            if(hdr.int_pai.Telemetry_Engine_Redirect == 0){
                //Caso nao seja o pacote que esta indo para o telemetry engine, atualiza stats e adiciona filho
                //Ja existe o pai. Atualiza o numero de filhos e insere novo filho.
                add_intfilho();
            }

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {


    
//    action drop() {
//        mark_to_drop();
//    }
    action remove_INT_headers(){
        //retrieve original ip next protocol
        hdr.ipv4.protocol = hdr.int_pai.next_header;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - INT_PAI_SIZE - hdr.int_pai.Quantidade_Filhos[15:0]*INT_FILHO_SIZE;
        hdr.int_pai.setInvalid();
//      if(hdr.int_filho[9].isValid())
            hdr.int_filho[9].setInvalid();
//      if(hdr.int_filho[8].isValid())
            hdr.int_filho[8].setInvalid();
//      if(hdr.int_filho[7].isValid())
            hdr.int_filho[7].setInvalid();
//      if(hdr.int_filho[6].isValid())
            hdr.int_filho[6].setInvalid();
//      if(hdr.int_filho[5].isValid())
            hdr.int_filho[5].setInvalid();
//      if(hdr.int_filho[4].isValid())
            hdr.int_filho[4].setInvalid();
//      if(hdr.int_filho[3].isValid())
            hdr.int_filho[3].setInvalid();
//      if(hdr.int_filho[2].isValid())
            hdr.int_filho[2].setInvalid();
//      if(hdr.int_filho[1].isValid())
            hdr.int_filho[1].setInvalid();
//      if(hdr.int_filho[0].isValid())
            hdr.int_filho[0].setInvalid();
    }

    action remove_INT_payload(){
    }


    apply {

        if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL){
            if(meta.isEndhost==1 ){
                hdr.ipv4.ttl = 100;
                if(hdr.int_pai.isValid() && hdr.int_pai.Telemetry_Engine_Redirect != 1){
                    remove_INT_headers();
                }
            }
        }else if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){

            hdr.ipv4.ttl = 150;

            //TODO: create a reg for telemetry engine addr
            hdr.ipv4.dstAddr = 0x0A000303;
            //hdr.int_pai.Telemetry_Engine_Redirect = 0;

            if(hdr.int_filho[MAX_HOPS-1].isValid()){
                hdr.int_filho[MAX_HOPS-1].packet_type_egress1 = standard_metadata.instance_type;
            }

            recirculate({standard_metadata, meta});

        }else if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_RECIRC){
            hdr.int_pai.Telemetry_Engine_Redirect = 1;

            hdr.ipv4.totalLen = IPV4_SIZE + INT_PAI_SIZE + hdr.int_pai.Quantidade_Filhos[15:0]*INT_FILHO_SIZE;
            truncate(ETHERNET_SIZE + ( 16w0000 ++ hdr.ipv4.totalLen));
            hdr.ipv4.ttl = 200;

        }

        if(hdr.int_filho[MAX_HOPS-1].isValid()){
            hdr.int_filho[MAX_HOPS-1].packet_type_egress2 = standard_metadata.instance_type;
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.int_pai);
        packet.emit(hdr.int_filho);
		packet.emit(hdr.tcp);
		packet.emit(hdr.udp);
//		packet.emit(hdr.payload);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
