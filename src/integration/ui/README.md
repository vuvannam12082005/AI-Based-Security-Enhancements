# AI Security Monitor - Streamlit UI

A web-based dashboard for monitoring and managing the AI Security system, providing real-time visibility into process events, security alerts, and enforcement actions.

## Features

- **Real-time Dashboard**: Live monitoring of system events, process activity, and resource usage
- **Security Alerts**: Automated detection of suspicious activities with enforcement actions
- **Service Management**: Start/stop sensor collection and configure system settings
- **Interactive Charts**: Resource usage timelines, event distributions, and process activity heatmaps
- **Process Control**: Throttle, kill, or release processes directly from the UI

## Prerequisites

1. **Python Dependencies**: Install Streamlit and required packages
   ```bash
   pip install streamlit plotly pandas requests
   ```

2. **Backend Services**: Ensure the sensor and enforcer services are running
   ```bash
   # Terminal 1: Start sensor service
   ./scripts/run_sensor.sh
   
   # Terminal 2: Start enforcer service (requires sudo)
   ./scripts/run_enforcer.sh
   ```

## Running the UI

### Basic Usage
```bash
# From the repository root
streamlit run src/integration/ui/app.py
```

### With Custom Configuration
```bash
# Set service endpoints
export SENSOR_URL="http://localhost:8001"
export ENFORCER_URL="http://localhost:8002"
export ML_URL="http://localhost:8003"
export ORCH_API_URL="http://localhost:8000"
export WS_URL="ws://localhost:8000/ws/realtime"

streamlit run src/integration/ui/app.py
```

### Production Deployment
```bash
# Run on specific host/port
streamlit run src/integration/ui/app.py --server.address 0.0.0.0 --server.port 8501
```

## Configuration

### Environment Variables

- `SENSOR_URL`: Sensor service URL (default: `http://localhost:8001`)
- `ENFORCER_URL`: Enforcer service URL (default: `http://localhost:8002`)
- `ML_URL`: ML service URL (default: `http://localhost:8003`)
- `ORCH_API_URL`: Orchestrator API URL (default: `http://localhost:8000`)
- `WS_URL`: WebSocket URL for real-time updates (default: `ws://localhost:8000/ws/realtime`)

### Service Endpoints

The UI connects to these backend services:

- **Sensor Service**: `http://localhost:8001`
  - `/sensor/status` - Service status
  - `/sensor/start` - Start data collection
  - `/sensor/stop` - Stop data collection  
  - `/sensor/events/latest` - Get recent events

- **Enforcer Service**: `http://localhost:8002`
  - `/enforcer/status` - Service status
  - `/enforcer/action` - Execute enforcement actions
  - `/enforcer/release` - Release process from enforcement

## Usage Guide

### 1. Dashboard Page
- **Service Status**: Monitor sensor and enforcer service health
- **System Metrics**: View CPU and memory usage gauges
- **Event Stream**: Real-time table of security events with filtering
- **Analytics**: Charts showing event distributions and resource usage trends
- **Process Monitor**: Active processes with resource consumption

### 2. Alerts Page
- **Alert Configuration**: Set CPU/memory thresholds and auto-actions
- **Active Alerts**: View current security alerts with severity levels
- **Enforcement Actions**: Throttle, kill, or release suspicious processes
- **Alert History**: Timeline of past security incidents

### 3. Settings Page
- **Connection Settings**: Configure API and WebSocket URLs
- **Service Management**: Start/stop sensor with mode selection (proc/eBPF)
- **Data Management**: Configure event buffer size and CSV export settings
- **Alert Thresholds**: Customize detection sensitivity
- **System Information**: View environment and connection status

## Troubleshooting

### Common Issues

1. **"Cannot connect to sensor service"**
   - Ensure sensor service is running: `./scripts/run_sensor.sh`
   - Check if port 8001 is accessible
   - Verify SENSOR_URL environment variable

2. **"Cannot connect to enforcer service"**
   - Ensure enforcer service is running with sudo: `./scripts/run_enforcer.sh`
   - Check if port 8002 is accessible
   - Verify the service has proper cgroup permissions

3. **"No events available"**
   - Start the sensor service from Settings page
   - Wait a few seconds for data collection to begin
   - Check sensor service logs for errors

4. **WebSocket connection failed**
   - WebSocket support is not yet implemented in backend
   - UI will automatically fallback to polling mode
   - Set WS_URL to match your WebSocket server when available

### Performance Tips

- Reduce event limit on Dashboard if UI becomes slow
- Use auto-refresh sparingly on large datasets
- Monitor memory usage with large event buffers
- Consider using eBPF mode for high-frequency monitoring

## Development

### Project Structure
```
src/integration/ui/
├── app.py              # Main Streamlit application
├── pages/
│   ├── dashboard.py    # Real-time monitoring dashboard
│   ├── alerts.py       # Security alerts and actions
│   └── settings.py     # System configuration
├── components/
│   ├── charts.py       # Reusable plotting functions
│   └── tables.py       # Data table components
├── utils.py            # API client and utilities
└── README.md           # This file
```

### Adding New Features

1. **New Chart Types**: Add functions to `components/charts.py`
2. **New Table Formats**: Extend `components/tables.py`
3. **Additional Pages**: Create new files in `pages/` directory
4. **API Extensions**: Update `utils.py` APIClient class

### Testing

```bash
# Test API connectivity
python -c "from src.integration.ui.utils import APIClient; api = APIClient('http://localhost'); print(api.get_sensor_status())"

# Test UI components
streamlit run src/integration/ui/app.py --server.headless true
```

## Security Considerations

- The UI connects to backend services without authentication
- Enforcement actions (kill/throttle) are executed immediately
- Consider adding confirmation dialogs for destructive actions
- Monitor access logs for the Streamlit application
- Use HTTPS in production deployments