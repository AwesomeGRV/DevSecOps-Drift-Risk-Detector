"""
Modern observability and monitoring module with OpenTelemetry integration
"""

import time
import psutil
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Request, Response
from fastapi.responses import PlainTextResponse
import logging
import json

class ObservabilityManager:
    """Enhanced observability manager with OpenTelemetry and Prometheus metrics"""
    
    def __init__(self):
        self.start_time = time.time()
        self.tracer = None
        self.meter = None
        self.logger = logging.getLogger(__name__)
        
        # Prometheus metrics
        self.request_count = Counter(
            'http_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status_code']
        )
        
        self.request_duration = Histogram(
            'http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint']
        )
        
        self.active_connections = Gauge(
            'active_connections',
            'Number of active connections'
        )
        
        self.system_cpu = Gauge(
            'system_cpu_percent',
            'System CPU usage percentage'
        )
        
        self.system_memory = Gauge(
            'system_memory_percent',
            'System memory usage percentage'
        )
        
        self.analysis_count = Counter(
            'analysis_total',
            'Total drift analysis performed',
            ['result', 'risk_level']
        )
        
        self.security_events = Counter(
            'security_events_total',
            'Total security events',
            ['event_type', 'severity']
        )
        
        self.file_uploads = Counter(
            'file_uploads_total',
            'Total file uploads',
            ['file_type', 'validation_result']
        )
        
    def setup_telemetry(self, app_name: str = "drift-detector") -> tuple:
        """Setup OpenTelemetry for observability"""
        try:
            # Setup tracing
            trace_provider = TracerProvider()
            trace.set_tracer_provider(trace_provider)
            self.tracer = trace.get_tracer(app_name)
            
            # Setup metrics
            metric_reader = PrometheusMetricReader()
            meter_provider = MeterProvider(metric_readers=[metric_reader])
            metrics.set_meter_provider(meter_provider)
            self.meter = metrics.get_meter(app_name)
            
            # Create custom metrics
            self.analysis_counter = self.meter.create_counter(
                "drift_analysis_count",
                description="Number of drift analyses performed"
            )
            
            self.security_event_counter = self.meter.create_counter(
                "security_event_count", 
                description="Number of security events"
            )
            
            self.logger.info("OpenTelemetry telemetry setup completed")
            return self.tracer, meter_provider
            
        except Exception as e:
            self.logger.error(f"Failed to setup telemetry: {e}")
            return None, None
    
    def instrument_app(self, app):
        """Instrument FastAPI application with OpenTelemetry"""
        try:
            FastAPIInstrumentor.instrument_app(app)
            LoggingInstrumentor.instrument()
            self.logger.info("FastAPI application instrumented successfully")
        except Exception as e:
            self.logger.error(f"Failed to instrument app: {e}")
    
    def record_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record HTTP request metrics"""
        self.request_count.labels(
            method=method, 
            endpoint=endpoint, 
            status_code=str(status_code)
        ).inc()
        
        self.request_duration.labels(
            method=method, 
            endpoint=endpoint
        ).observe(duration)
    
    def record_analysis(self, result: str, risk_level: str):
        """Record drift analysis metrics"""
        self.analysis_count.labels(result=result, risk_level=risk_level).inc()
        
        if self.analysis_counter:
            self.analysis_counter.add(1, {"result": result, "risk_level": risk_level})
    
    def record_security_event(self, event_type: str, severity: str):
        """Record security event metrics"""
        self.security_events.labels(event_type=event_type, severity=severity).inc()
        
        if self.security_event_counter:
            self.security_event_counter.add(1, {"event_type": event_type, "severity": severity})
    
    def record_file_upload(self, file_type: str, validation_result: str):
        """Record file upload metrics"""
        self.file_uploads.labels(file_type=file_type, validation_result=validation_result).inc()
    
    def update_system_metrics(self):
        """Update system resource metrics"""
        try:
            self.system_cpu.set(psutil.cpu_percent())
            self.system_memory.set(psutil.virtual_memory().percent)
        except Exception as e:
            self.logger.error(f"Failed to update system metrics: {e}")
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary"""
        try:
            uptime = time.time() - self.start_time
            
            return {
                "timestamp": datetime.now().isoformat(),
                "uptime_seconds": uptime,
                "system": {
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_usage_percent": psutil.disk_usage('/').percent,
                    "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
                },
                "application": {
                    "active_connections": self.active_connections._value.get(),
                    "total_requests": sum(self.request_count._metrics.values()),
                    "avg_response_time": self._calculate_avg_response_time(),
                    "error_rate": self._calculate_error_rate()
                },
                "security": {
                    "total_security_events": sum(self.security_events._metrics.values()),
                    "failed_logins": self._get_failed_login_count(),
                    "blocked_ips": self._get_blocked_ip_count()
                }
            }
        except Exception as e:
            self.logger.error(f"Failed to get metrics summary: {e}")
            return {"error": str(e)}
    
    def _calculate_avg_response_time(self) -> float:
        """Calculate average response time"""
        try:
            # This would be calculated from the histogram data
            # For now, return a placeholder
            return 0.0
        except Exception:
            return 0.0
    
    def _calculate_error_rate(self) -> float:
        """Calculate error rate percentage"""
        try:
            total_requests = sum(self.request_count._metrics.values())
            if total_requests == 0:
                return 0.0
            
            error_requests = sum(
                count for (method, endpoint, status_code), count 
                in self.request_count._metrics.items() 
                if status_code.startswith(('4', '5'))
            )
            
            return (error_requests / total_requests) * 100
        except Exception:
            return 0.0
    
    def _get_failed_login_count(self) -> int:
        """Get failed login attempts count"""
        try:
            return sum(
                count for (event_type, severity), count 
                in self.security_events._metrics.items() 
                if event_type == 'login_failed'
            )
        except Exception:
            return 0
    
    def _get_blocked_ip_count(self) -> int:
        """Get blocked IP count"""
        try:
            return sum(
                count for (event_type, severity), count 
                in self.security_events._metrics.items() 
                if event_type == 'ip_blocked'
            )
        except Exception:
            return 0
    
    async def start_monitoring(self):
        """Start background monitoring task"""
        asyncio.create_task(self._monitoring_loop())
    
    async def _monitoring_loop(self):
        """Background monitoring loop"""
        while True:
            try:
                self.update_system_metrics()
                await asyncio.sleep(30)  # Update every 30 seconds
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    def create_trace_context(self, operation_name: str):
        """Create a trace context for operations"""
        if self.tracer:
            return self.tracer.start_as_current_span(operation_name)
        return None
    
    def get_prometheus_metrics(self) -> PlainTextResponse:
        """Get Prometheus metrics endpoint"""
        return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# Global observability manager instance
observability_manager = ObservabilityManager()

def setup_observability_middleware(app):
    """Setup observability middleware for FastAPI app"""
    
    @app.middleware("http")
    async def observability_middleware(request: Request, call_next):
        start_time = time.time()
        
        # Update active connections
        observability_manager.active_connections.inc()
        
        try:
            response = await call_next(request)
            
            # Record request metrics
            duration = time.time() - start_time
            observability_manager.record_request(
                method=request.method,
                endpoint=request.url.path,
                status_code=response.status_code,
                duration=duration
            )
            
            return response
            
        except Exception as e:
            # Record error
            duration = time.time() - start_time
            observability_manager.record_request(
                method=request.method,
                endpoint=request.url.path,
                status_code=500,
                duration=duration
            )
            
            observability_manager.record_security_event(
                event_type="application_error",
                severity="high"
            )
            
            raise
            
        finally:
            # Update active connections
            observability_manager.active_connections.dec()
    
    # Add metrics endpoint
    @app.get("/metrics")
    async def metrics_endpoint():
        return observability_manager.get_prometheus_metrics()
    
    # Add detailed metrics endpoint
    @app.get("/metrics/detailed")
    async def detailed_metrics():
        return observability_manager.get_metrics_summary()
