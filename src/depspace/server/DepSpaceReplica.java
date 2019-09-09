package depspace.server;

import java.io.*;
import java.util.Collection;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import bftsmart.statemanagement.StateManager;
import bftsmart.tom.MessageContext;
import bftsmart.tom.ReplicaContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.server.defaultservices.DefaultRecoverable;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.client.ConfidentialServiceProxy;
import confidential.server.ConfidentialRecoverable;
import confidential.statemanagement.ConfidentialSnapshot;
import depspace.extension.EDSExtensionManager;
import depspace.general.Context;
import depspace.general.DepSpaceConfiguration;
import depspace.general.DepSpaceException;
import depspace.general.DepSpaceOperation;
import depspace.general.DepSpaceReply;
import depspace.general.DepSpaceRequest;
import depspace.general.DepTuple;


public class DepSpaceReplica extends ConfidentialRecoverable implements DepSpaceEventHandler {

	private final int replicaID;
	private final DepSpaceManager spacesManager;

	public DepSpaceReplica(int id, boolean join) {
		super(id);
		this.replicaID = id;
		this.spacesManager = DepSpaceConfiguration.IS_EXTENSIBLE ? new EDSExtensionManager(id, this) : new DepSpaceManager(id, this);
		new ServiceReplica(id,this, this);
	}

	@Override
	public ConfidentialMessage appExecuteOrdered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(plainData);
			 ObjectInput in = new ObjectInputStream(bis)) {
			in.readInt();//id
			DepSpaceOperation operation = DepSpaceOperation.getOperation(in.read());
			Context context = new Context(in, operation, msgCtx);

			byte[] serializedTuple;
			Object arg = null;
			switch (operation) {
				case OUT:
					int len = in.readInt();
					serializedTuple = new byte[len];
					in.readFully(serializedTuple);
					DepTuple maskedTuple = new DepTuple(serializedTuple);
					maskedTuple.setShare(shares[0]);
					arg = maskedTuple;
					break;
				case RDP:
				case RDALL:
				case INP:
				case INALL:
					len = in.readInt();
					serializedTuple = new byte[len];
					in.readFully(serializedTuple);
					arg = new DepTuple(serializedTuple);
					break;
				case CAS:
					DepTuple[] tuples = new DepTuple[2];
					//reading template
					len = in.readInt();
					serializedTuple = new byte[len];
					in.readFully(serializedTuple);
					maskedTuple = new DepTuple(serializedTuple);
					tuples[0] = maskedTuple;

					//reading tuple
					len = in.readInt();
					serializedTuple = new byte[len];
					in.readFully(serializedTuple);
					maskedTuple = new DepTuple(serializedTuple);
					maskedTuple.setShare(shares[0]);
					tuples[1] = maskedTuple;
					arg = tuples;
					break;
				case CREATE:
				case DELETE:
					arg = in.readObject();
					break;
				default:
					System.err.println("Unhandled operation type " + operation);
			}

			Object result = execute(operation, context, arg, msgCtx);
			return composeResponse(result instanceof DepSpaceException ? DepSpaceOperation.EXCEPTION : operation,
					result);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public ConfidentialMessage appExecuteUnordered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
		try (ByteArrayInputStream bis = new ByteArrayInputStream(plainData);
			 ObjectInput in = new ObjectInputStream(bis)) {
			in.readInt();//id
			DepSpaceOperation operation = DepSpaceOperation.getOperation(in.read());
			Context context = new Context(in, operation, msgCtx);

			byte[] serializedTuple;
			Object arg = null;
			switch (operation) {
				case RDP:
				case RDALL:
					int len = in.readInt();
					serializedTuple = new byte[len];
					in.readFully(serializedTuple);
					arg = new DepTuple(serializedTuple);
					break;
				default:
					System.err.println("Unhandled operation type " + operation);
			}

			Object result = execute(operation, context, arg, msgCtx);
			return composeResponse(result instanceof DepSpaceException ? DepSpaceOperation.EXCEPTION : operation,
					result);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private ConfidentialMessage composeResponse(DepSpaceOperation operation, Object result) {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
			 ObjectOutput out = new ObjectOutputStream(bos)) {
			out.write((byte)operation.ordinal());
			ConfidentialData[] shares = null;
			switch (operation) {
				case RDP:
				case INP:
				case CAS:
					out.writeBoolean(result != null);
					if (result != null) {
						DepTuple tuple = (DepTuple) result;
						shares = new ConfidentialData[]{tuple.getShare()};
						DepTuple tupleShareless = tuple.getTupleWithoutShare();
						byte[] serializedTuple = tupleShareless.serialize();
						out.writeInt(serializedTuple.length);
						out.write(serializedTuple);
					}
					break;
				case RDALL:
				case INALL:
					out.writeBoolean(result != null);
					if (result != null) {
						Collection<DepTuple> tuples = (Collection<DepTuple>)result;
						shares = new ConfidentialData[tuples.size()];
						out.writeInt(tuples.size());
						int k = 0;
						for (DepTuple tuple : tuples) {
							shares[k++] = tuple.getShare();
							DepTuple tupleShareless = tuple.getTupleWithoutShare();
							byte[] serializedTuple = tupleShareless.serialize();
							out.writeInt(serializedTuple.length);
							out.write(serializedTuple);
						}
					}
					break;
				case EXCEPTION:
					out.writeObject(result);
					break;
			}
			out.flush();
			bos.flush();
			return shares == null ? new ConfidentialMessage(bos.toByteArray())
					: new ConfidentialMessage(bos.toByteArray(), shares);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public ConfidentialSnapshot getConfidentialSnapshot() {
		return spacesManager.getSnapshot();
	}

	@Override
	public void installConfidentialSnapshot(ConfidentialSnapshot snapshot) {
		spacesManager.installSnapshot(snapshot);
	}

	private Object execute(DepSpaceOperation operation, Context context, Object arg, MessageContext msgCtx) {
		try {
			return spacesManager.invokeOperation(context.tsName, operation, arg, context);
		} catch(Exception e) {
			return (e instanceof DepSpaceException) ? (DepSpaceException) e : new DepSpaceException("Server-side exception: " + e);
		}
	}

	/**************************
	 * DEPSPACE EVENT HANDLER *
	 **************************/

	@Override
	public void handleEvent(DepSpaceOperation operation, DepTuple tuple, Context ctx) {
		//handleResult(operation, tuple, ctx, true);
	}

	/********
	 * MAIN *
	 ********/

	public static void main(String[] args) {
		if(args.length < 2) {
			System.out.println("Use: java DepSpaceServer <processId> <config-home> <join option (optional)>");
			System.exit(-1);
		}

		DepSpaceConfiguration.init(args[1]);
		boolean join = (args.length > 2) ? Boolean.valueOf(args[2]) : false;
		new DepSpaceReplica(Integer.parseInt(args[0]), join);
	}

}
