package depspace.server;

import confidential.ConfidentialData;
import depspace.general.DepTuple;

import java.util.Properties;

public class TupleSpaceSnapshot {
    private DepTuple[] tuples;
    private ConfidentialData[] shares;
    private String tupleSpaceName;
    private Properties layersConfig;

    public TupleSpaceSnapshot(DepTuple[] tuples, ConfidentialData[] shares) {
        this.tuples = tuples;
        this.shares = shares;
    }

    public DepTuple[] getTuples() {
        return tuples;
    }

    public ConfidentialData[] getShares() {
        return shares;
    }

    public String getTupleSpaceName() {
        return tupleSpaceName;
    }

    public Properties getLayersConfig() {
        return layersConfig;
    }

    public void setLayersConfig(Properties layersConfig) {
        this.layersConfig = layersConfig;
    }

    public void setTupleSpaceName(String tupleSpaceName) {
        this.tupleSpaceName = tupleSpaceName;
    }
}
