import streamlit as st
import joblib
import numpy as np

# Load the trained model
model = joblib.load("models/model.pkl")

# Set page configuration
st.set_page_config(page_title="Credit Card Fraud Detector", layout="centered")

# Main title
st.title("Credit Card Fraud Detection System")
st.subheader("Using Machine Learning (Random Forest Classifier)")

st.markdown("""
Welcome to the fraud detection system. Enter transaction details below to check if it's likely **fraudulent** or **legit**.
""")

# Input form
with st.form("fraud_form"):
    st.markdown("### Transaction Features (V1 - V28, Amount):")

    # Generate inputs for V1 to V28
    features = []
    for i in range(1, 29):
        val = st.number_input(f"V{i}", value=0.0, step=0.01)
        features.append(val)

    # Amount
    amount = st.number_input("Transaction Amount", value=0.0, step=0.01)
    features.append(amount)

    # Submit
    submitted = st.form_submit_button("Check Transaction")

# Prediction
if submitted:
    input_array = np.array([features])  # reshape for prediction
    prediction = model.predict(input_array)[0]
    confidence = model.predict_proba(input_array)[0][prediction]

    if prediction == 1:
        st.error(f" This transaction is likely **FRAUDULENT** with {confidence*100:.2f}% confidence.")
    else:
        st.success(f" This transaction appears to be **LEGITIMATE** with {confidence*100:.2f}% confidence.")
