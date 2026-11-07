
import streamlit as st

st.set_page_config(
    page_title="CyberScore Lite",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CyberScore Lite")
st.subheader("External Cyber Exposure Assessment")

st.info("MVP — Environment initialized successfully.")

domain = st.text_input(
    "Domain to assess",
    placeholder="example.com",
)

authorized = st.checkbox(
    "I confirm that I am authorized to assess this domain."
)

if st.button("Run Assessment"):
    if not domain.strip():
        st.warning("Please enter a domain.")
    elif not authorized:
        st.error("Authorization confirmation is required.")
    else:
        st.info(
            "Assessment engine is not implemented yet. "
            "No network requests have been sent."
        )
