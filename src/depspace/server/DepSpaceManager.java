package depspace.server;

import confidential.ConfidentialData;
import confidential.statemanagement.ConfidentialSnapshot;
import depspace.general.*;
import depspace.policyenforcement.PolicyEnforcementLayer;

import java.io.*;
import java.util.*;


public class DepSpaceManager {

	private final int processID;
	private final Map<String, DepSpaceServerLayer> tupleSpaces;
	private final Map<String, Properties> tupleSpaceProperties;
	private DepSpaceEventHandler eventHandler;

	public DepSpaceManager(int processID, DepSpaceEventHandler eventHandler) {
		this.processID = processID;
		this.tupleSpaces = new HashMap<String, DepSpaceServerLayer>();
		this.tupleSpaceProperties = new HashMap<>();
		this.eventHandler = eventHandler;
	}


	protected void setEventHandler(DepSpaceEventHandler eventHandler) {
		this.eventHandler = eventHandler;
	}

	public synchronized Object invokeOperation(String tsName, DepSpaceOperation operation, Object arg, Context ctx) throws DepSpaceException {
		//		System.out.println(System.currentTimeMillis() + " INVOKE[" + ctx.invokerID + "]: " + operation + " on " + tsName + " with " + arg);
		switch(operation) {
			case CREATE:
				// Create tuple space if it not yet exists
				DepSpaceServerLayer tupleSpace = tupleSpaces.get(tsName);
				if(tupleSpace == null) {
					Properties prop = (Properties)arg;
					tupleSpace = createTupleSpace(prop);
					tupleSpaces.put(tsName, tupleSpace);
					tupleSpaceProperties.put(tsName, prop);
				}
				return new DepTuple();
			case DELETE:
				tupleSpaces.remove(tsName);
				return new DepTuple();
			default:
				tupleSpace = tupleSpaces.get(tsName);
				if(tupleSpace != null) return invokeTupleSpaceOperation(tupleSpace, operation, arg, ctx);
				return null;
		}
	}

	@SuppressWarnings("unchecked")
	private Object invokeTupleSpaceOperation(DepSpace tupleSpace, DepSpaceOperation operation, Object arg, Context ctx) throws DepSpaceException {
		Object result = null;
		switch(operation) {
			case OUT:
				tupleSpace.out((DepTuple) arg, ctx);
				break;
			case RENEW:
				result = tupleSpace.renew((DepTuple) arg, ctx);
				break;
			case RDP:
				result = tupleSpace.rdp((DepTuple) arg, ctx);
				break;
			case INP:
				result = tupleSpace.inp((DepTuple) arg, ctx);
				break;
			case RD:
				result = tupleSpace.rd((DepTuple) arg, ctx);
				break;
			case IN:
				result = tupleSpace.in((DepTuple) arg, ctx);
				break;
			case CAS:
				DepTuple[] tuples = (DepTuple[]) arg;
				result = tupleSpace.cas(tuples[0], tuples[1], ctx);
				break;
			case REPLACE:
				tuples = (DepTuple[]) arg;
				result = tupleSpace.replace(tuples[0], tuples[1], ctx);
				break;
			case OUTALL:
				tupleSpace.outAll((List<DepTuple>) arg, ctx);
				break;
			case RDALL:
				result = (arg == null) ? tupleSpace.rdAll() : tupleSpace.rdAll((DepTuple) arg, ctx);
				break;
			case INALL:
				result = tupleSpace.inAll((DepTuple) arg, ctx);
				break;
			case CLEAN:
				throw new UnsupportedOperationException("clean() not yet implemented");
				//			break;
			default:
				System.err.println("Unhandled operation type: " + operation);
		}
		return result;
	}

	private DepSpaceServerLayer createTupleSpace(Properties properties) {
		// Create implementation layer
		DepSpaceServerLayer tupleSpace;
		if(DepSpaceConfiguration.tupleSpaceImpl.equals("List"))
			tupleSpace = new DepSpaceImplLayer(eventHandler, new DepSpaceListImpl(DepSpaceConfiguration.realTimeNew));
		else if(DepSpaceConfiguration.tupleSpaceImpl.equals("Map"))
			tupleSpace = new DepSpaceImplLayer(eventHandler, new DepSpaceMapImpl(DepSpaceConfiguration.realTimeNew, DepSpaceConfiguration.depth));
		else
			tupleSpace = new DepSpaceImplLayer(eventHandler, new DepSpaceListImpl(DepSpaceConfiguration.realTimeNew));

		// Add replace-trigger layer
		if(DepSpaceConfiguration.replaceTrigger) tupleSpace = new ReplaceTriggerLayer(tupleSpace);

		// Add policy-enforcement layer
		String policy = DepSpaceProperties.getPolicy(properties);
		if(policy != null) {
			try {
				tupleSpace = new PolicyEnforcementLayer(tupleSpace, policy);
			} catch(DepSpaceException dse) {
				dse.printStackTrace();
			}
		}

		// Add confidentiality layer
		//boolean useConfidentiality = DepSpaceProperties.getUseConfidentiality(properties);

		return tupleSpace;
	}

	public void installSnapshot(ConfidentialSnapshot snapshot) {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(snapshot.getPlainData());
			 ObjectInput in = new ObjectInputStream(bis)) {
			tupleSpaceProperties.clear();
			tupleSpaces.clear();
			ConfidentialData[] allShares = snapshot.getShares();
			int numTupleSpaces = in.readInt();
			int j = 0;
			while (numTupleSpaces-- > 0) {
				String tsName = in.readUTF();
				Properties prop = (Properties)in.readObject();
				tupleSpaceProperties.put(tsName, prop);
				DepSpaceServerLayer layers = createTupleSpace(prop);
				int numTuples = in.readInt();
				DepTuple[] tuples = new DepTuple[numTuples];
				ConfidentialData[] shares = new ConfidentialData[numTuples];
				for (int i = 0; i < numTuples; i++) {
					byte[] serializedTuple = new byte[in.readInt()];
					in.readFully(serializedTuple);
					tuples[i] = new DepTuple(serializedTuple);
					shares[i] = allShares[j++];
				}
				layers.installSnapshot(new TupleSpaceSnapshot(tuples, shares));
				tupleSpaces.put(tsName, layers);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public ConfidentialSnapshot getSnapshot() {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
			 ObjectOutput out = new ObjectOutputStream(bos)) {
			List<TupleSpaceSnapshot> tsSnaps = new ArrayList<>(tupleSpaces.size());
			int numShares = 0;
			for (Map.Entry<String, DepSpaceServerLayer> entry : tupleSpaces.entrySet()) {
				TupleSpaceSnapshot tsSnap = entry.getValue().getSnapshot();
				numShares += tsSnap.getShares().length;
				tsSnap.setTupleSpaceName(entry.getKey());
				tsSnap.setLayersConfig(tupleSpaceProperties.get(entry.getKey()));
				tsSnaps.add(tsSnap);
			}

			ConfidentialData[] shares = new ConfidentialData[numShares];
			out.writeInt(tupleSpaces.size());
			int i = 0;

			for (TupleSpaceSnapshot tsSnap : tsSnaps) {
				out.writeUTF(tsSnap.getTupleSpaceName());
				out.writeObject(tsSnap.getLayersConfig());
				out.writeInt(tsSnap.getTuples().length);
				for (DepTuple tuple : tsSnap.getTuples()) {
					byte[] serializedTuple = tuple.serialize();
					out.writeInt(serializedTuple.length);
					out.write(serializedTuple);
				}
				for (ConfidentialData share : tsSnap.getShares()) {
					shares[i++] = share;
				}
			}

			out.flush();
			bos.flush();
			return new ConfidentialSnapshot(bos.toByteArray(), shares);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}
