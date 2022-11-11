package navid.fana;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.net.SocketException;

public class SampleSnmpClient_2 {
    public static final int SNMP_VERSION = SnmpConstants.version1;
    public static final String SNMP_READ_COMMUNITY = "public";
//    HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2022-11-11,21:18:33.0,+3:30
//    .1.3.6.1.2.1.25.1.2
//    OID of MIB RFC 1213; Scalar Object = .iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0
//    .1.3.6.1.2.1.1.1.0
    public static final String SAMPLE_DEVICE_OID = ".1.3.6.1.2.1.1.1.0";
    public static final String SNMP_AGENT_ADDRESS = "127.0.0.1";
    public static final String SNMP_AGENT_PORT = "161";
    public static final int SNMP_PDU_TYPE = PDU.GET;

    public static void main(String[] args) throws IOException {
        String address = SNMP_AGENT_ADDRESS + "/" + SNMP_AGENT_PORT;
        Address address1 = new UdpAddress(address);
        TransportMapping transportMapping = new DefaultUdpTransportMapping();
        transportMapping.listen();

        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString(SNMP_READ_COMMUNITY));
        target.setAddress(address1);
        target.setVersion(SNMP_VERSION);
        target.setRetries(2);
        target.setTimeout(5000);

        PDU pdu = new PDU();
        ResponseEvent responseEvent;
        Snmp snmp ;
        pdu.add(new VariableBinding(new OID(SAMPLE_DEVICE_OID)));
        pdu.setType(SNMP_PDU_TYPE);
        snmp = new Snmp(transportMapping);
        System.out.println("Sending SNMP GET request to "+ SNMP_AGENT_ADDRESS+"/"+SNMP_AGENT_PORT+".\n" + pdu);
        responseEvent = snmp.get(pdu,target);
        if (responseEvent != null) {
//            System.out.println("Response is not null.");
            if(responseEvent.getResponse().getErrorStatusText().equalsIgnoreCase("success")){
                PDU responsePDU = responseEvent.getResponse();
                System.out.println("\nSNMP GET Response:\n"+ responsePDU.getVariableBindings().get(0));
            }
                else {
                System.out.println("SNMP GET Request failed.\n Printing the response:\n\t" + responseEvent.getResponse());
                System.out.println("Printing SNMP GET Request PDU:\n" + responseEvent.getRequest());
            }
        } else {
            System.out.println("SNMP GET Request time oue.");
        }
        snmp.close();
    }
}
