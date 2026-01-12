class SecurityBrain:
    def analyze(self, snapshot):
        decisions = {}

        for ip, data in snapshot.items():
            score = 0
            reason = []

            if data["packet_count"] > 100:
                score += 0.4
                reason.append("High packet rate")

            if data["ports_touched"] > 10:
                score += 0.6
                reason.append("Port scanning behavior")

            status = "NORMAL"
            if score >= 0.6:
                status = "SUSPICIOUS"

            decisions[ip] = {
                "status": status,
                "confidence": round(score, 2),
                "reason": ", ".join(reason)
            }

        return decisions
