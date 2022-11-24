package navid.fana.agent;

import java.io.File;
import java.io.IOException;

import org.snmp4j.TransportMapping;
import org.snmp4j.agent.*;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.agent.mo.MOTableRow;
import org.snmp4j.agent.mo.snmp.RowStatus;
import org.snmp4j.agent.mo.snmp.SnmpCommunityMIB;
import org.snmp4j.agent.mo.snmp.SnmpNotificationMIB;
import org.snmp4j.agent.mo.snmp.SnmpTargetMIB;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.log.Log4jLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.transport.TransportMappings;


public class SimpleAgent extends BaseAgent {
    // not needed but very useful of course
	static {
		LogFactory.setLogFactory(new Log4jLogFactory());
	}

	private String address;
	private static OID SNMP_V3_AUTH_PROTOCOL = AuthSHA.ID;
	private  static OID SNMP_V3_PRIVATE_KEY_PROTOCOL = PrivAES128.ID;

	public SimpleAgent(String address) throws IOException {
		// These files does not exist and are not used but has to be specified
		// Read snmp4j docs for more info
		super(new File("conf.agent"), new File("bootCounter.agent"), new CommandProcessor(new OctetString(MPv3.createLocalEngineID())));
		this.address = address;
	}

	/**
	 * We let clients of this agent register the MO they
	 * need so this method does nothing
	 */
	@Override
	protected void registerManagedObjects() {
	}

	/**
	 * Clients can register the MO they need
	 */
	public void registerManagedObject(ManagedObject mo) {
		try {
			server.register(mo, null);
		} catch (DuplicateRegistrationException ex) {
			throw new RuntimeException(ex);
		}
	}

	public void unregisterManagedObject(MOGroup moGroup) {
		moGroup.unregisterMOs(server, getContext(moGroup));
	}

	/*
	 * Empty implementation
	 */
	@Override
	protected void addNotificationTargets(SnmpTargetMIB targetMIB,SnmpNotificationMIB notificationMIB) {
	}

	/**
	 * Minimal View based Access Control
	 *
	 * http://www.faqs.org/rfcs/rfc2575.html
	 */
	@Override
	protected void addViews(VacmMIB vacm) {

		vacm.addGroup(SecurityModel.SECURITY_MODEL_SNMPv2c,
				new OctetString("cpublic"),
				new OctetString("v1v2group"),
				StorageType.nonVolatile);

		vacm.addAccess(new OctetString("v1v2group"),
				new OctetString("public"),
				SecurityModel.SECURITY_MODEL_ANY,
				SecurityLevel.NOAUTH_NOPRIV,
				MutableVACM.VACM_MATCH_EXACT,
				new OctetString("fullReadView"),
				new OctetString("fullWriteView"),
				new OctetString("fullNotifyView"),
				StorageType.nonVolatile);

//		Manually added - custom snmpV3 user
//		Pay Attention to the context !!!
		vacm.addGroup(SecurityModel.SECURITY_MODEL_USM,
				new OctetString("snmp3user"),
				new OctetString("v3group"),
//				StorageType.nonVolatile);
				StorageType.nonVolatile);

		vacm.addAccess(new OctetString("v3group"),
				new OctetString(""),
				SecurityModel.SECURITY_MODEL_USM,
				SecurityLevel.NOAUTH_NOPRIV,
				MutableVACM.VACM_MATCH_EXACT,
				new OctetString("fullReadView"),
				new OctetString("fullWriteView"),
				new OctetString("fullNotifyView"),
				StorageType.nonVolatile);

		vacm.addViewTreeFamily(new OctetString("fullReadView"),
				new OID("1.3"),
				new OctetString(),
				VacmMIB.vacmViewIncluded,
				StorageType.nonVolatile);
		vacm.addViewTreeFamily(new OctetString("fullWriteView"),
				new OID("1.3"),
				new OctetString(),
				VacmMIB.vacmViewIncluded,
				StorageType.nonVolatile);
	}

	/**
	 * User based Security Model, only applicable to
	 * SNMP v.3
	 *
	 */
	protected void addUsmUser(USM usm) {
//		Statically adding a user
		OctetString username, password, privPassword;
		OID authProtocol, privProtocol;
		username = new OctetString("snmp3user");
		password = new OctetString("1qaz1qaz");
		privPassword = new OctetString("2wsx2wsx");
//		Statically added protocols
		authProtocol = SNMP_V3_AUTH_PROTOCOL;
		privProtocol = SNMP_V3_PRIVATE_KEY_PROTOCOL;
		UsmUser user = new UsmUser(username,authProtocol,password,privProtocol,privPassword);
		usm.addUser(username,user);

	}

	protected void initTransportMappings() throws IOException {
		transportMappings = new TransportMapping[1];
		Address addr = GenericAddress.parse(address);
		TransportMapping tm = TransportMappings.getInstance()
				.createTransportMapping(addr);
		transportMappings[0] = tm;
	}

	/**
	 * Start method invokes some initialization methods needed to
	 * start the agent
	 * @throws IOException
	 */
	public void start() throws IOException {
		init();
		// This method reads some old config from a file and causes
		// unexpected behavior.
		// loadConfig(ImportModes.REPLACE_CREATE);
		addShutdownHook();
		getServer().addContext(new OctetString("public"));
		finishInit();
		run();
		sendColdStartNotification();
	}



	protected void unregisterManagedObjects() {
		// here we should unregister those objects previously registered...
	}

	/**
	 * The table of community strings configured in the SNMP
	 * engine's Local Configuration Datastore (LCD).
	 *
	 * We only configure one, "public".
	 */
	protected void addCommunities(SnmpCommunityMIB communityMIB) {
		Variable[] com2sec = new Variable[] {
				new OctetString("public"), // community name
				new OctetString("cpublic"), // security name
				getAgent().getContextEngineID(), // local engine ID
				new OctetString("public"), // default context name
				new OctetString(), // transport tag
				new Integer32(StorageType.nonVolatile), // storage type
				new Integer32(RowStatus.active) // row status
		};
		MOTableRow row = communityMIB.getSnmpCommunityEntry().createRow(
				new OctetString("public2public").toSubIndex(true), com2sec);
		communityMIB.getSnmpCommunityEntry().addRow(row);
	}

//	public static void main(String[] args) throws IOException, InterruptedException {
//		SimpleAgent agent = new SimpleAgent("127.0.0.1/2001");
////		Variable variable = new OctetString("FUCK U!");
////		agent.registerManagedObject(new MOScalar(new OID("1.2.3"), MOAccessImpl.ACCESS_READ_ONLY,variable));
//		agent.start();
//		while(true) {
//			System.out.println("Agent running...");
//			Thread.sleep(5000);
//		}
//	}

}
