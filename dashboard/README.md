# Security Hardening Dashboard

Modern React dashboard for Security Hardening Agentless system.

## Features

- 📊 **Dashboard Overview**: Real-time statistics and compliance metrics
- 🖥️ **Hosts Management**: View all monitored hosts with compliance scores
- 📋 **Audit Reports**: Detailed audit results with filtering
- 🔧 **Remediations**: Track remediation actions and rollback status
- 📈 **Charts & Visualizations**: Compliance trends and OS distribution
- 🔐 **Authentication**: API key-based authentication

## Tech Stack

- **React 18** - UI framework
- **React Router** - Navigation
- **Vite** - Build tool
- **Recharts** - Charts and visualizations
- **Axios** - HTTP client
- **Lucide React** - Icons

## Setup

### Prerequisites

- Node.js 18+ and npm/yarn
- Backend API running on `http://localhost:8080`

### Installation

```bash
cd dashboard
npm install
```

### Development

```bash
npm run dev
```

Dashboard will be available at `http://localhost:3000`

### Build for Production

```bash
npm run build
```

Output will be in `dist/` directory.

### Preview Production Build

```bash
npm run preview
```

## Configuration

### Environment Variables

Create a `.env` file in the `dashboard/` directory:

```env
VITE_API_URL=http://localhost:8080
```

If not set, defaults to `http://localhost:8080`

## Usage

1. **Login**: Enter your API key (created via `/auth/setup` endpoint)
2. **Dashboard**: View overview statistics and recent audits
3. **Hosts**: Monitor all hosts and their compliance scores
4. **Audits**: Browse audit reports and view detailed results
5. **Remediations**: Track remediation actions and rollback status

## API Integration

The dashboard integrates with the following backend endpoints:

- `GET /reports/hosts` - Get hosts overview
- `GET /reports/compliance-stats` - Get compliance statistics
- `GET /reports/audits` - Get audit reports
- `GET /reports/audits/:id` - Get audit details
- `GET /reports/remediations` - Get remediation logs
- `GET /healthz` - Health check

All requests require `X-API-Key` header for authentication.

## Project Structure

```
dashboard/
├── src/
│   ├── components/      # Reusable components
│   │   ├── Layout.jsx
│   │   └── StatCard.jsx
│   ├── contexts/        # React contexts
│   │   └── AuthContext.jsx
│   ├── pages/           # Page components
│   │   ├── Dashboard.jsx
│   │   ├── Hosts.jsx
│   │   ├── Audits.jsx
│   │   ├── AuditDetail.jsx
│   │   ├── Remediations.jsx
│   │   └── Login.jsx
│   ├── services/        # API services
│   │   └── api.js
│   ├── App.jsx          # Main app component
│   ├── main.jsx         # Entry point
│   └── index.css        # Global styles
├── index.html
├── package.json
├── vite.config.js
└── README.md
```

## Development Notes

- The dashboard uses React Router for client-side routing
- API key is stored in localStorage
- All API calls go through the `api.js` service
- Charts use Recharts library
- Icons from Lucide React

## Troubleshooting

### Cannot connect to backend

- Ensure backend is running on port 8080
- Check `VITE_API_URL` in `.env` file
- Verify API key is valid

### Build errors

- Clear `node_modules` and reinstall: `rm -rf node_modules && npm install`
- Check Node.js version: `node --version` (should be 18+)

## License

Same as main project.

