import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
import pandas as pd
import pickle

# Load model and encoders
with open("fraudshield_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("fraudshield_encoders.pkl", "rb") as f:
    encoders = pickle.load(f)

# GUI Setup
app = ttk.Window(themename="darkly")
app.title("FraudShield - Transaction Monitor")
app.geometry("400x500")

ttk.Label(app, text="Amount").pack(pady=5)
amount_entry = ttk.Entry(app)
amount_entry.pack()

ttk.Label(app, text="Device Type").pack(pady=5)
device_combo = ttk.Combobox(app, values=["mobile", "web", "atm"])
device_combo.pack()

ttk.Label(app, text="Transaction Time").pack(pady=5)
time_combo = ttk.Combobox(app, values=["morning", "afternoon", "evening", "night"])
time_combo.pack()

ttk.Label(app, text="Location").pack(pady=5)
location_combo = ttk.Combobox(app, values=["urban", "suburban", "rural"])
location_combo.pack()

ttk.Label(app, text="Transaction Frequency").pack(pady=5)
freq_entry = ttk.Entry(app)
freq_entry.pack()

def predict_anomaly():
    try:
        data = {
            "amount": float(amount_entry.get()),
            "device_type": encoders['device_type'].transform([device_combo.get()])[0],
            "transaction_time": encoders['transaction_time'].transform([time_combo.get()])[0],
            "location": encoders['location'].transform([location_combo.get()])[0],
            "frequency": int(freq_entry.get())
        }
        df = pd.DataFrame([data])
        prediction = model.predict(df)[0]

        if prediction == -1:
            messagebox.showwarning("Result", " Anomalous Transaction Detected!")
        else:
            messagebox.showinfo("Result", " Transaction is Safe.")

    except Exception as e:
        messagebox.showerror("Error", str(e))

ttk.Button(app, text="Check Transaction", command=predict_anomaly).pack(pady=20)
app.mainloop()
