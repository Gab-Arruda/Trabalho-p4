/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;
const bit<8> TYPE_INT = 150; //0x96;
#define MAX_HOPS 8

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
    /* Outros dados*/
}

header int_filhos_t{
    varbit<1040> Filhos;
}

header int_novo_filho_t {
    bit<32> ID_Switch;
    bit<9> Porta_Entrada;
    bit<9> Porta_Saida;
    bit<48> Timestamp;
    /* Outros dados*/
    bit<6> padding; /* O tamanho do cabecalho em bits deve ser multiplo de 8 */
}

struct metadata {
    bit<32> remaining;
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    int_pai_t    int_pai;
    int_filhos_t int_lista_filhos;
    int_novo_filho_t int_novo_filho;
    tcp_t        tcp;
    udp_t        udp;
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
//			TYPE_TCP: parse_tcp;
//			TYPE_UDP: parse_udp;
            TYPE_INT: parse_int_pai;
			default: accept;
		}
    }

//	state parse_tcp {
//		packet.extract(hdr.tcp);
//		transition  accept;
//	}
//
//	state parse_udp {
//		packet.extract(hdr.udp);
//		transition  accept;
//	}

/*TODO: acho que nao eh no parser que adiciona o cabecalho.
    pelo que eu entendi o parser é só pra preencher os headers e dar
    accept ou reject 
*/
    state parse_int_pai {
        packet.extract(hdr.int_pai);
        meta.remaining = hdr.int_pai.Quantidade_Filhos;
        packet.extract(hdr.int_lista_filhos, hdr.int_pai.Quantidade_Filhos * hdr.int_pai.Tamanho_Filho );
        transition accept;
    }

//    state parse_int_filho {
//        packet.extract(hdr.int_filho.next);
//        meta.remaining = meta.remaining -1;
//
//        transition select(meta.remaining){
//            0: parse_L4;
//            default: parse_int_filho;
//        }
//    }
//    
//    state parse_L4{
//        transition select(hdr.int_pai.next_header){
//            TYPE_TCP: parse_tcp;
//            TYPE_UDP: parse_udp;
//            default: accept;
//        }
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
    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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

    action add_intfilho(bit<32> swid){
        hdr.int_pai.Quantidade_Filhos = hdr.int_pai.Quantidade_Filhos + 1;
        hdr.int_novo_filho.setValid();
        hdr.int_novo_filho.ID_Switch = swid; //???
        hdr.int_novo_filho.Porta_Entrada = standard_metadata.ingress_port;
        hdr.int_novo_filho.Porta_Saida = standard_metadata.egress_spec;
        hdr.int_novo_filho.Timestamp = standard_metadata.ingress_global_timestamp;
        hdr.int_novo_filho.padding = 0;

    }

    table intfilho {
        actions = {
	    add_intfilho; 
	    NoAction; 
        }
        default_action = NoAction();      
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();

            if(!hdr.int_pai.isValid()){
                //TODO: inserir o header int_pai e 1 header int_filho.
                //Verificar se eh assim mesmo que se adiciona headers.
                //Item1 da primeira pagina da spec do trabalho comenta setValid.
                hdr.int_pai.setValid();
                hdr.int_pai.Tamanho_Filho = 104; //verificar se existe uma forma de extrair o tamanho das structs
                hdr.int_pai.Quantidade_Filhos = 0;

                //salva o protocolo que viria apos o ipv4 no next_header do pai e 
                //seta o protocol do ipv4 para int. No proximo hop vai identificar a 
                // existencia do int_pai no parser.
                hdr.int_pai.next_header = hdr.ipv4.protocol;
                hdr.ipv4.protocol= TYPE_INT;
            }
            //Ja existe o pai. Atualiza o numero de filhos e insere novo filho.
            intfilho.apply();
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
        packet.emit(hdr.int_lista_filhos);
        packet.emit(hdr.int_novo_filho);
//		packet.emit(hdr.tcp);
//		packet.emit(hdr.udp);
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
