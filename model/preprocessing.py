import pandas as pd
import numpy as np
import hashlib
import joblib
from sklearn.preprocessing import LabelEncoder, FunctionTransformer
from typing import Optional


def preprocess_packets(df, proto_le):
    """Return DataFrame and fitted/used protocol LabelEncoder."""
    df = df.copy()

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['year']        = df['timestamp'].dt.year
    df['month']       = df['timestamp'].dt.month
    df['day']         = df['timestamp'].dt.day
    df['hour']        = df['timestamp'].dt.hour
    df['minute']      = df['timestamp'].dt.minute
    df['second']      = df['timestamp'].dt.second
    df['microsecond'] = df['timestamp'].dt.microsecond
    df['weekday']     = df['timestamp'].dt.dayofweek

    for col, p in [('source_ip', 'src_ip'), ('destination_ip', 'dst_ip')]:
        ip_split = df[col].str.split('.', expand=True).astype('Int64')
        ip_split.columns = [f'{p}_{i}' for i in range(1,5)]
        df = pd.concat([df, ip_split], axis=1)

    for col, p in [('source_mac', 'src_mac'), ('destination_mac', 'dst_mac')]:
        mac_split = (
            df[col].str.split(':', expand=True)
                    .apply(lambda s: s.apply(lambda x: int(x, 16) if isinstance(x, str) else np.nan))
        )
        mac_split.columns = [f'{p}_{i}' for i in range(1,7)]
        df = pd.concat([df, mac_split], axis=1)

    if proto_le is None:
        proto_le = LabelEncoder().fit(df['protocol'])
    df['protocol_id'] = proto_le.transform(df['protocol'])

    # Hash payload to encode
    df['payload_hash'] = df['payload'].apply(
        lambda s: int(hashlib.sha256(str(s).encode()).hexdigest(), 16) & 0xFFFFFFFF
    )

    numeric_cols = (
        ['flow_bytes','payload_size','source_port','destination_port'] +
        ['year','month','day','hour','minute','second','microsecond','weekday'] +
        [f'src_ip_{i}' for i in range(1,5)] + [f'dst_ip_{i}' for i in range(1,5)] +
        [f'src_mac_{i}' for i in range(1,7)] + [f'dst_mac_{i}' for i in range(1,7)] +
        ['protocol_id','payload_hash']
    )

    X_num = df[numeric_cols].fillna(-1).astype(np.int64)
    return X_num, proto_le