package navid.fana;

import org.snmp4j.*;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;

public class SimpleSnmpAgent implements CommandResponder {

    private TransportMapping transportMapping;
    private Target target;
    private Snmp snmp;
    private USM usm;

    public static final String HOST_IP = "127.0.0.1";
    public static final String HOST_PORT = "161";
    public static final String HOST_RESPONSE_PORT = "162";
    public static final int SNMP_VERSION = SnmpConstants.version3;
    public static final String SNMP_READ_COMMUNITY = "public";
    public static final String SAMPLE_DEVICE_OID = ".1.3.6.1.2.1.1.1.0";
    public static final String SNMP_AGENT_ADDRESS = "127.0.0.1";
    public static final String SNMP_AGENT_PORT = "161";
    public static final int SNMP_PDU_TYPE = PDU.GET;
    public static final int SNMP_V3_SECURITY_LEVEL = SecurityLevel.AUTH_PRIV;
    public static final String SNMP_V3_USERNAME = "snmpuser";
    public static final String SNMP_V3_PASSWORD = "1qaz2wsx";
    public static final OID SNMP_V3_AUTH_PROTOCOL = AuthSHA.ID;
    public static final OID SNMP_V3_PRIVATE_KEY_PROTOCOL = PrivAES128.ID;
    public static final String SNMP_V3_PRIVATE_PASSWORD = "2wsx3edc";

    public SimpleSnmpAgent() throws IOException {
        String address = HOST_IP + "/" + HOST_PORT;
        Address address1 = new UdpAddress(address);
        TransportMapping transportMapping = new DefaultUdpTransportMapping((UdpAddress) address1);
        snmp = new Snmp(transportMapping);
        byte[] localEngineID = MPv3.createLocalEngineID();
        usm = new USM(SecurityProtocols.getInstance(), new OctetString(localEngineID), 0);
        SecurityModels.getInstance().addSecurityModel(usm);
        snmp.setLocalEngine(localEngineID, 0, 0);
        snmp.addCommandResponder(this);

//        user credentials
        OctetString authPassphrase = new OctetString(SNMP_V3_PASSWORD);
        OctetString privPassphrase = new OctetString(SNMP_V3_PRIVATE_PASSWORD);
        OID authProtocol = SNMP_V3_AUTH_PROTOCOL;
        OID privProtocol = SNMP_V3_PRIVATE_KEY_PROTOCOL;
        UsmUser usmUser = new UsmUser(new OctetString(SNMP_V3_USERNAME), authProtocol, authPassphrase, privProtocol, privPassphrase);
        snmp.getUSM().addUser(usmUser.getSecurityName(),usmUser);
    }

    @Override
    public void processPdu(CommandResponderEvent event) {
        System.out.println("#########################################################");
        System.out.println("SNMP request received:\n"+event);
        System.out.println("---------------------------------------------------------");
        System.out.println("Request peer address :\n"+event.getPeerAddress());
        System.out.println("---------------------------------------------------------");
        System.out.println("Request security name :\n"+event.getSecurityName());
        System.out.println("---------------------------------------------------------");

        System.out.println("Request state reference :\n"+event.getStateReference());
        System.out.println("---------------------------------------------------------");

        System.out.println("Request transport mapping :\n"+event.getTransportMapping());
        System.out.println("---------------------------------------------------------");

        System.out.println("Request transport mapping listen address :\n"+event.getTransportMapping().getListenAddress());
        System.out.println("---------------------------------------------------------");

//                response event
        ArrayList<VariableBinding> variableBindings = new ArrayList<>();
        System.out.println("----------------------------1-----------------------------");
//        variableBindings.add(new VariableBinding(event.getPDU().getVariableBindings().get(0).getOid() , new OctetString("YYYYYeeeeeeeeeee")));
//        variableBindings.add(new VariableBinding(event.getPDU().getVariableBindings().get(0).getOid() , new OctetString("FUCK U")));
        System.out.println("----------------------------2-----------------------------");
//        CommunityTarget comm = new CommunityTarget(event.getPeerAddress(), new OctetString(event.getSecurityName()));
        CommunityTarget comm = new CommunityTarget(new UdpAddress(HOST_IP+"/"+HOST_RESPONSE_PORT), new OctetString(event.getSecurityName()));
        System.out.println("----------------------------3-----------------------------");
//        comm.setSecurityLevel(event.getSecurityLevel());
//        System.out.println("----------------------------4-----------------------------");
//        comm.setSecurityModel(event.getSecurityModel());
//        System.out.println("----------------------------5-----------------------------");
//        PDU resp = new PDU(PDU.RESPONSE,variableBindings );
        System.out.println("---------------------------------------------------------");

//        try {
////            System.out.println(String.format("Sending response PDU to %s/%s: %s", comm.getAddress(), new String(event.getSecurityName()), resp));
////            this.snmp.send(resp, comm);
////            resp.setRequestID(event.getPDU().getRequestID());
////            System.out.println(String.format("Sending response PDU to %s/%s: %s", comm.getAddress(), new String(event.getSecurityName()), resp));
////            this.snmp.send(resp, comm);
//        } catch (IOException e) {
//            e.printStackTrace();
//            System.out.println("----------------------------Problem in sending the response-----------------------------");
//        }
        event.setProcessed(true);
    }

    private void listen() throws IOException {
        this.snmp.listen();
        System.out.println("----------------------------SNMP Agent started-----------------------------");
    }

    public void operate() throws IOException {
        this.listen();
//  until sig kill
        while (true) {
            if (false==true){
                break;
            }
        }
        this.close();
    }

    private void close() throws IOException {
        this.snmp.close();
        System.out.println("SNMP Agent closed");
    }
}
