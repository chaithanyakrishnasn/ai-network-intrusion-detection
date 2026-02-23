from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import time


class AnomalyEngine:

    def __init__(self):
        self.model = IsolationForest(
            contamination=0.02,
            random_state=42
        )
        self.scaler = StandardScaler()

        self.training_data = []
        self.max_training_samples = 500

        self.is_trained = False
        self.last_train_time = 0
        self.retrain_interval = 60  # seconds

    def add_sample(self, feature_vector):
        self.training_data.append(feature_vector)

        if len(self.training_data) > self.max_training_samples:
            self.training_data.pop(0)

    def train(self):
        if len(self.training_data) < 50:
            return

        X = np.array(self.training_data)

        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)

        self.is_trained = True
        self.last_train_time = time.time()

    def should_retrain(self):
        if not self.is_trained:
            return True

        return (time.time() - self.last_train_time) > self.retrain_interval

    def score(self, feature_vector):
        if not self.is_trained:
            return None

        X_scaled = self.scaler.transform([feature_vector])

        prediction = self.model.predict(X_scaled)[0]
        score = self.model.decision_function(X_scaled)[0]

        return prediction, score
