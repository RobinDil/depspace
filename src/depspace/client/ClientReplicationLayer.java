package depspace.client;

import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.util.TOMUtil;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import depspace.confidentiality.ProtectionVector;
import depspace.general.Context;
import depspace.general.DepSpaceException;
import depspace.general.DepSpaceOperation;
import depspace.general.DepSpaceProperties;
import depspace.general.DepSpaceReply;
import depspace.general.DepSpaceRequest;
import depspace.general.DepTuple;
import depspace.util.Payload;
import vss.facade.SecretSharingException;


public class ClientReplicationLayer implements DepSpaceClientLayer {
	public static final String PRIVATE = "PR";

	// Counter for request sequence numbers
	private final AtomicInteger sequenceNumber;

	// BFT-SMaRt
	private final ConfidentialServiceProxy proxy;
	
	
	public ClientReplicationLayer(ConfidentialServiceProxy proxy) {
		this.sequenceNumber = new AtomicInteger();
		this.proxy = proxy;
	}


	private Object executeOperation(DepSpaceOperation operation, Object arg, Context ctx) throws DepSpaceException {
		return executeOperation(operation, arg, ctx, operation.getRequestType());
	}
	
	private synchronized Object executeOperation(DepSpaceOperation operation, Object arg, Context ctx, TOMMessageType type) throws DepSpaceException {

		Response response = null;

		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
			 ObjectOutputStream out = new ObjectOutputStream(bos)) {
			int id = sequenceNumber.getAndIncrement();
			out.writeInt(id);
			out.write((byte)operation.ordinal());
			ctx.serialize(out);
			byte[] confidentialData = null;

			switch (operation) {
				case OUT:
					DepTuple tuple = (DepTuple)arg;
					Object[] fields = tuple.getFields();
					Object[] fingerprint = fingerprint(ctx.protectionVectors[0], fields);
					DepTuple maskedTuple = new DepTuple(fingerprint, tuple.getC_rd(), tuple.getC_in(),
							tuple.getExpirationTime(), tuple.getN_Matches());
					byte[] serializedMaskedTuple = maskedTuple.serialize();
					out.writeInt(serializedMaskedTuple.length);
					out.write(serializedMaskedTuple);
					confidentialData = tupleToBytes(fields);
					break;
				case RDP:
				case RD:
				case RDALL:
				case IN:
				case INP:
				case INALL:
					tuple = (DepTuple)arg;
					fingerprint = fingerprint(ctx.protectionVectors[0], tuple.getFields());
					maskedTuple = new DepTuple(fingerprint, tuple.getC_rd(), tuple.getC_in(),
							tuple.getExpirationTime(), tuple.getN_Matches());
					serializedMaskedTuple = maskedTuple.serialize();
					out.writeInt(serializedMaskedTuple.length);
					out.write(serializedMaskedTuple);
					break;
				case CAS:
					DepTuple[] tuples = (DepTuple[]) arg;
					//writing template
					tuple = tuples[0];
					fingerprint = fingerprint(ctx.protectionVectors[0], tuple.getFields());
					maskedTuple = new DepTuple(fingerprint, tuple.getC_rd(), tuple.getC_in(),
							tuple.getExpirationTime(), tuple.getN_Matches());
					serializedMaskedTuple = maskedTuple.serialize();
					out.writeInt(serializedMaskedTuple.length);
					out.write(serializedMaskedTuple);

					//writing new tuple
					tuple = tuples[1];
					fingerprint = fingerprint(ctx.protectionVectors[1], tuple.getFields());
					maskedTuple = new DepTuple(fingerprint, tuple.getC_rd(), tuple.getC_in(),
							tuple.getExpirationTime(), tuple.getN_Matches());
					serializedMaskedTuple = maskedTuple.serialize();
					out.writeInt(serializedMaskedTuple.length);
					out.write(serializedMaskedTuple);
					confidentialData = tupleToBytes(tuple.getFields());
					break;
				case RENEW:
				case SIGNED_RD:
				case CLEAN:
				case REPLACE:
					throw new UnsupportedOperationException();
				case CREATE:
				case DELETE:
					out.writeObject(arg);
					break;
				default:
					System.err.println("Unhandled operation type " + operation);
			}
			out.flush();
			bos.flush();
			if (type == TOMMessageType.ORDERED_REQUEST)
				response = confidentialData == null ? proxy.invokeOrdered(bos.toByteArray())
						: proxy.invokeOrdered(bos.toByteArray(), confidentialData);
			else if (type == TOMMessageType.UNORDERED_REQUEST)
				response = confidentialData == null ? proxy.invokeUnordered(bos.toByteArray())
						: proxy.invokeUnordered(bos.toByteArray(), confidentialData);
			else
				throw new DepSpaceException("Unknown TOMMessageType " + type);
		} catch (IOException | SecretSharingException e) {
			throw new DepSpaceException("Failed to serialize request", e);
		}

		if (response == null)
			return null;
		try (ByteArrayInputStream bis = new ByteArrayInputStream(response.getPainData());
			 ObjectInput in = new ObjectInputStream(bis)) {
			DepSpaceOperation responseOperation = DepSpaceOperation.getOperation(in.read());
			switch (responseOperation) {
				case EXCEPTION:
					throw (DepSpaceException)in.readObject();
				case RDP:
				case RD:
				case INP:
				case IN:
					if (in.readBoolean()) {
						Object[] fields = extractTuple(response.getConfidentialData()[0]);
						byte[] serializedTuple = new byte[in.readInt()];
						in.readFully(serializedTuple);
						DepTuple tuple = new DepTuple(serializedTuple);
						tuple.setFields(fields);
						return tuple;
					} else
						return null;
				case RDALL:
				case INALL:
					List<DepTuple> tuples;
					if (in.readBoolean()) {
						int nTuples = in.readInt();
						tuples = new ArrayList<>(nTuples);
						for (int i = 0; i < nTuples; i++) {
							Object[] fields = extractTuple(response.getConfidentialData()[i]);
							byte[] serializedTuple = new byte[in.readInt()];
							in.readFully(serializedTuple);
							DepTuple tuple = new DepTuple(serializedTuple);
							tuple.setFields(fields);
							tuples.add(tuple);
						}
					} else
						tuples = new ArrayList<>();
					return tuples;
				default:
					return null;
			}
		} catch (Exception e) {
			throw new DepSpaceException("Failed to deserialize response", e);
		}
	}
	
	/*************************************
	 * DEPSPACE INTERFACE IMPLEMENTATION *
	 *************************************/

	@Override
	public void out(DepTuple tuple, Context ctx) throws DepSpaceException {
		executeOperation(DepSpaceOperation.OUT, tuple, ctx);
	}

	@Override
	public void outAll(List<DepTuple> tuplesBag, Context ctx) throws DepSpaceException {
		executeOperation(DepSpaceOperation.OUTALL, tuplesBag, ctx);		
	}

	@Override
	public DepTuple renew(DepTuple template, Context ctx) throws DepSpaceException {
		return (DepTuple) executeOperation(DepSpaceOperation.RENEW, template, ctx);
	}

	@Override
	public DepTuple rdp(DepTuple template, Context ctx) throws DepSpaceException {
		// Try to obtain a result
		DepTuple result = (DepTuple) executeOperation(DepSpaceOperation.RDP, template, ctx);
		if(result == null) return result;
		
		// Validation check <--- Why is such a check performed in rdp(), but not in rd() or rdAll()? 
		if(!result.isExpired(System.currentTimeMillis())) return result;
		// System.out.println("RDP :: TUPLE VALIDATION IS EXPIRED, WE NEED TO SEND A NON READONLY REQUEST");
		return (DepTuple) executeOperation(DepSpaceOperation.RDP, template, ctx, TOMMessageType.ORDERED_REQUEST);
	}

	@Override
	public DepTuple inp(DepTuple template, Context ctx) throws DepSpaceException {
		return (DepTuple) executeOperation(DepSpaceOperation.INP, template, ctx);
	}

	@Override
	public DepTuple rd(DepTuple template, Context ctx) throws DepSpaceException {
		return (DepTuple) executeOperation(DepSpaceOperation.RD, template, ctx);
	}

	@Override
	public DepTuple in(DepTuple template, Context ctx) throws DepSpaceException {
		return (DepTuple) executeOperation(DepSpaceOperation.IN, template, ctx);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Collection<DepTuple> rdAll(DepTuple template, Context ctx) throws DepSpaceException {
		return (Collection<DepTuple>) executeOperation(DepSpaceOperation.RDALL, template, ctx);
	}

	@Override
	public Collection<DepTuple> rdAll() {
		throw new UnsupportedOperationException("rdAll() is not implemented by the client replication layer");
	}

	@SuppressWarnings("unchecked")
	@Override
	public Collection<DepTuple> inAll(DepTuple template, Context ctx) throws DepSpaceException {
		return (Collection<DepTuple>) executeOperation(DepSpaceOperation.INALL, template, ctx);
	}
	
	@Override
	public DepTuple cas(DepTuple template, DepTuple tuple, Context ctx) throws DepSpaceException {
		return (DepTuple) executeOperation(DepSpaceOperation.CAS, new DepTuple[] { template, tuple }, ctx);
	}

	@Override
	public DepTuple replace(DepTuple template, DepTuple tuple, Context ctx) throws DepSpaceException {
		return (DepTuple) executeOperation(DepSpaceOperation.REPLACE, new DepTuple[] { template, tuple }, ctx);
	}

	
	/********************************************
	 * DEPSPACE CLIENT INTERFACE IMPLEMENTATION *
	 ********************************************/

	@Override
	public void createSpace(Properties properties) throws DepSpaceException {
		Context createContext = Context.createDefaultContext(DepSpaceProperties.getTSName(properties), DepSpaceOperation.CREATE, false, (DepTuple[]) null);
		executeOperation(DepSpaceOperation.CREATE, properties, createContext);
	}

	@Override
	public void deleteSpace(String name) throws DepSpaceException {
		Context deleteContext = Context.createDefaultContext(name, DepSpaceOperation.DELETE, false, (DepTuple[]) null);
		executeOperation(DepSpaceOperation.DELETE, name, deleteContext);
	}

	@Override
	public DepTuple signedRD(DepTuple template, Context ctx) throws DepSpaceException {
		return (DepTuple) executeOperation(DepSpaceOperation.SIGNED_RD, template, ctx);
	}

	@Override
	public void clean(DepTuple proof, Context ctx) throws DepSpaceException {
		executeOperation(DepSpaceOperation.CLEAN, proof, ctx);
	}

	private Object[] fingerprint(ProtectionVector protectionVector, Object[] fields) {

		if(protectionVector.getLength() != fields.length) {
			throw new RuntimeException("Invalid field type specification");
		}

		Object[] fingerprint = new Object[fields.length];

		for(int i=0; i < protectionVector.getLength(); i++) {
			if(DepTuple.WILDCARD.equals(fields[i])){
				fingerprint[i] = DepTuple.WILDCARD;
			}else{
				switch(protectionVector.getType(i)){
					case ProtectionVector.PU:{
						fingerprint[i] = fields[i];
					}break;
					case ProtectionVector.CO:{
						fingerprint[i] = digest(fields[i].toString().getBytes());
					}break;
					case ProtectionVector.PR:{
						fingerprint[i] = PRIVATE;
					}break;
					default:{
						throw new RuntimeException("Invalid field type specification");
					}
				}
			}
		}

		return fingerprint;
	}

	private BigInteger digest(byte[] data) {
		return new BigInteger(TOMUtil.computeHash(data));
	}

	private byte[] tupleToBytes(Object[] fields) {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = new ObjectOutputStream(bos)) {
			out.writeInt(fields.length);
			for (Object field : fields) {
				out.writeObject(field);
			}
			out.flush();
			bos.flush();
			return bos.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException("cannot write tuple fields: ", e);
		}
	}

	private Object[] extractTuple(byte[] tupleBytes) throws Exception {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(tupleBytes);
			 ObjectInput in = new ObjectInputStream(bis)) {
			Object[] fields = new Object[in.readInt()];
			for (int i = 0; i < fields.length; i++)
				fields[i] = in.readObject();
			return fields;
		} catch(Exception e) {
			throw new RuntimeException("cannot read tuple fields: ", e);
		}
	}
}
