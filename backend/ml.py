import numpy as np
from sklearn.ensemble import IsolationForest

model = IsolationForest(contamination=0.1, random_state=42)

# Fake training data (normal traffic baseline)
X_train = np.array([
    [10, 80], [12, 443], [15, 53], [20, 22],
    [11, 80], [14, 443]
])

model.fit(X_train)

def score(flow_rate, port):
    X = np.array([[flow_rate, port]])
    s = model.decision_function(X)[0]
    return "HIGH" if s < -0.1 else "LOW"
