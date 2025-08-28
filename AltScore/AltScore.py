import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as tb
import pickle
import numpy as np

# Load model and encoders
with open('altscore_model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('label_encoders.pkl', 'rb') as f:
    encoders = pickle.load(f)

# Build UI
app = tb.Window(themename="cosmo")
app.title("AltScore - Credit Risk Predictor")
app.geometry("500x500")

# Inputs
fields = {}

def create_label_dropdown(name, options):
    label = ttk.Label(app, text=name)
    label.pack(pady=5)
    var = tk.StringVar()
    dropdown = ttk.Combobox(app, textvariable=var, values=options, state="readonly")
    dropdown.current(0)
    dropdown.pack()
    fields[name] = var

def create_label_entry(name):
    label = ttk.Label(app, text=name)
    label.pack(pady=5)
    var = tk.StringVar()
    entry = ttk.Entry(app, textvariable=var)
    entry.pack()
    fields[name] = var

# Dropdowns
create_label_dropdown("Airtime Recharge Frequency", ['daily', 'weekly', 'monthly'])
create_label_dropdown("Utility Payment Consistency", ['always', 'sometimes', 'rarely'])
create_label_dropdown("Location", ['urban', 'rural'])

# Numerical Inputs
create_label_entry("Average Monthly Airtime Spent")
create_label_entry("Peer Transfers Per Month")
create_label_entry("Average Monthly Spending")

# Prediction function
def predict():
    try:
        input_data = [
            encoders['airtime_recharge_freq'].transform([fields['Airtime Recharge Frequency'].get()])[0],
            int(fields['Average Monthly Airtime Spent'].get()),
            int(fields['Peer Transfers Per Month'].get()),
            encoders['utility_payment_consistency'].transform([fields['Utility Payment Consistency'].get()])[0],
            int(fields['Average Monthly Spending'].get()),
            encoders['location'].transform([fields['Location'].get()])[0],
        ]

        prediction = model.predict([input_data])[0]
        risk_label = encoders['credit_risk'].inverse_transform([prediction])[0]
        messagebox.showinfo("Credit Risk Result", f"Predicted Credit Risk: {risk_label}")
    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{e}")

ttk.Button(app, text="Predict Credit Risk", command=predict, bootstyle="success").pack(pady=20)

app.mainloop()
