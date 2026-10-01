# Sellora

Full-stack affiliate marketplace under `sellora/`, isolated from the existing BuildMatrix application.

## Stack
React 18 + Tailwind utilities, FastAPI REST API, MongoDB/Motor, JWT authentication, bcrypt, and role-based access for seller/creator/admin.

## Local run
1. `cd sellora/backend`
2. Create and activate a Python virtual environment.
3. `pip install -r requirements.txt`
4. Set `MONGODB_URI`, `MONGODB_DB=sellora`, `APP_SECRET`, and `APP_BASE_URL=http://localhost:8000`.
5. Optional development seed: set `DEV_SEED=true`, then POST `/api/seed` once.
6. Run `uvicorn app:app --reload --host 0.0.0.0 --port 8000`.
7. Open `http://localhost:8000`.

## Production environment
Required: `MONGODB_URI`, `MONGODB_DB`, `APP_SECRET`, `APP_BASE_URL`. Keep secrets server-side. `DEV_SEED` should be false in production.

## MongoDB collections
users, seller_profiles, creator_profiles, products, categories, affiliate_links, clicks, orders, conversions, commissions, wallets, payout_requests, notifications, admin_actions.

## Affiliate flow
Creator generates a unique code -> `/go/{code}` records a click -> destination redirect -> test conversion creates an order/conversion/commission as PENDING -> admin approval changes conversion/commission to APPROVED and credits the creator wallet -> creator can request payout.

## Render
Build: `pip install -r sellora/backend/requirements.txt`
Start: `cd sellora/backend && uvicorn app:app --host 0.0.0.0 --port $PORT`
Health: `/api/health`

## MVP limitations
Payouts are provider-ready but not connected to a payment processor. Uploaded images use the service filesystem and should move to durable object storage for production. The conversion endpoint is a test/QA purchase path; connect real seller checkout webhooks before treating external orders as authoritative. Advanced time-series charting is not yet wired.
