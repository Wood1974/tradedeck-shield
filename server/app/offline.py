# Offline captures never mint evidence locally. Clients may retain original bytes + user testimony
# in OS-protected local storage and must obtain a fresh server nonce before final sealing.
OFFLINE_POLICY={"local_sealing":False,"fresh_nonce_required":True,"original_bytes_required":True}
