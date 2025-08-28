import pandas as pd
import numpy as np

np.random.seed(42)

# Generate synthetic data
n_users = 500
data = {
    'user_id': range(1, n_users + 1),
    'airtime_recharge_freq': np.random.choice(['daily', 'weekly', 'monthly'], n_users),
    'avg_monthly_airtime_spent': np.random.randint(500, 10000, n_users),
    'peer_transfers_per_month': np.random.randint(0, 50, n_users),
    'utility_payment_consistency': np.random.choice(['always', 'sometimes', 'rarely'], n_users),
    'avg_monthly_spending': np.random.randint(2000, 50000, n_users),
    'location': np.random.choice(['urban', 'rural'], n_users),
}

df = pd.DataFrame(data)

# Assign risk level based on rules
def risk_level(row):
    if row['utility_payment_consistency'] == 'always' and row['avg_monthly_airtime_spent'] > 3000 and row['peer_transfers_per_month'] > 5:
        return 'Low'
    elif row['utility_payment_consistency'] == 'rarely' or row['avg_monthly_spending'] < 5000:
        return 'High'
    else:
        return 'Medium'

df['credit_risk'] = df.apply(risk_level, axis=1)

df.to_csv("altscore_dataset.csv", index=False)
print("Dataset saved as altscore_dataset.csv")
