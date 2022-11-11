package navid.fana;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.net.SocketException;


public class App 
{
    public static void main( String[] args ) throws IOException {
        System.out.println( "Hello World!" );

        Snmp snmp;
        TransportMapping transportMapping;
        Target target;
        Address address;

        ScopedPDU scopedPDU;
        scopedPDU = new ScopedPDU();
        scopedPDU.add(new VariableBinding(new OID("1.1")));
        scopedPDU.setType(PDU.GET);
        scopedPDU.setContextName(new OctetString("public"));
        address = new UdpAddress();
        address.setValue("127.0.0.0/161");
        transportMapping = new DefaultUdpTransportMapping((UdpAddress) address);

//        Target Instantiation
        target = new UserTarget();
        target.setAddress(address);
        target.setRetries(1);
        target.setTimeout(500);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(SecurityLevel.noAuthNoPriv.getSnmpValue());
        target.setSecurityName(new OctetString("MD5DES"));
        target.setSecurityModel(SecurityModel.SECURITY_MODEL_ANY);

//        SNMP Instantiation
        snmp = new Snmp(transportMapping);
        snmp.listen();
        ResponseEvent responseEvent = snmp.send(scopedPDU,target);

    }
}
