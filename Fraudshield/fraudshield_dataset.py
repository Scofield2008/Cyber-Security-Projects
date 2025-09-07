import pandas as pd
import numpy as np

np.random.seed(42)
n_users = 500

# Generate transaction features
df = pd.DataFrame({
    'amount': np.random.normal(5000, 1500, n_users).clip(500, 15000),
    'device_type': np.random.choice(['mobile', 'web', 'atm'], n_users, p=[0.6, 0.3, 0.1]),
    'transaction_time': np.random.choice(['morning', 'afternoon', 'evening', 'night'], n_users),
    'location': np.random.choice(['urban', 'suburban', 'rural'], n_users, p=[0.6, 0.3, 0.1]),
    'frequency': np.random.poisson(10, n_users).clip(1, 30)
})

df.to_csv('fraudshield_dataset.csv', index=False)
print("Dataset saved as fraudshield_dataset.csv")
