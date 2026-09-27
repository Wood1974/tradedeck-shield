# TradeDeck integration
The API now calls a server-to-server authorization seam for both challenge issuance and capture. Production fails closed unless TradeDeck confirms the authenticated account may act on the requested job/point. Client-supplied roles are never authority. Configure `TRADEDECK_AUTHZ_URL` and `TRADEDECK_INTERNAL_API_KEY`.
