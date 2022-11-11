package navid.fana;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.USM;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import java.io.IOException;

public class SampleSnmpClient {

    private Snmp snmp;
    private TransportMapping transportMapping;
    private Target target;
    private Address address;
    private ScopedPDU scopedPDU;

    public SampleSnmpClient() throws IOException {
//        PDU Instantiation

    }

    public void listen() throws IOException {
        snmp.listen();
        ResponseEvent responseEvent = snmp.send(scopedPDU,target);
        System.out.println("Received response: "+ responseEvent.getResponse());
    }

}
