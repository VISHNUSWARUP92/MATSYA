import React, { useEffect, useMemo, useState } from "react";
import {
  CircleMarker,
  MapContainer,
  Popup,
  TileLayer,
  useMap,
} from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import "./ThreatMap.css";
import { MapPin, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";

const DEFAULT_API_BASE = (
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

function isValidCoordinate(latitude, longitude) {
  return (
    Number.isFinite(latitude) &&
    Number.isFinite(longitude) &&
    latitude >= -90 &&
    latitude <= 90 &&
    longitude >= -180 &&
    longitude <= 180
  );
}

function FitMarkers({ markers }) {
  const map = useMap();

  useEffect(() => {
    map.invalidateSize();

    const validMarkers = (markers || []).filter((marker) =>
      isValidCoordinate(marker.latitude, marker.longitude)
    );

    if (!validMarkers.length) {
      map.setView([22, 15], 2, { animate: true });
      return;
    }

    const bounds = L.latLngBounds(
      validMarkers.map((marker) => [marker.latitude, marker.longitude])
    );

    if (bounds.isValid()) {
      map.fitBounds(bounds.pad(0.25), { maxZoom: 6, animate: true });
    }
  }, [markers, map]);

  return null;
}

function normalizeList(value, field) {
  const values = Array.isArray(value) ? value : value ? [value] : [];

  return [...new Set(
    values
      .map((item) => {
        if (typeof item === "string" || typeof item === "number") {
          return String(item).trim();
        }
        if (item && typeof item === "object") {
          return String(
            item[field] || item.ip || item.domain || item.url || ""
          ).trim();
        }
        return "";
      })
      .filter(Boolean)
  )];
}

/*
 * Only indicators from the CURRENTLY selected/analysed email are sent.
 * Saved cases and synthetic/demo datasets are intentionally not used.
 */
function gatherCurrentIndicators(currentAnalysis) {
  const report = currentAnalysis?.report || currentAnalysis || {};
  const nested = report?.indicators || report?.iocs || {};

  return {
    ips: normalizeList(
      report.ips || report.extracted_ips || nested.ips,
      "ip"
    ).slice(0, 50),
    domains: normalizeList(
      report.domains || report.extracted_domains || nested.domains,
      "domain"
    ).slice(0, 30),
    urls: normalizeList(
      report.urls || report.extracted_urls || nested.urls,
      "url"
    ).slice(0, 20),
  };
}

function isConnectedFeedStatus(value) {
  if (value === true) return true;
  return ["connected", "online", "available", "ok"].includes(
    String(value || "").toLowerCase()
  );
}

export default function ThreatMap({
  analysis = null,
  apiBase = DEFAULT_API_BASE,
  onNavigate,
  onInspectIp,
}) {
  const [data, setData] = useState({ markers: [], feed_status: {} });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const indicators = useMemo(
    () => gatherCurrentIndicators(analysis),
    [analysis]
  );
  const signature = useMemo(() => JSON.stringify(indicators), [indicators]);
  const resolvedApiBase = String(apiBase || DEFAULT_API_BASE).replace(/\/+$/, "");

  useEffect(() => {
    const parsed = JSON.parse(signature);
    const hasIndicators = Boolean(
      parsed.ips.length || parsed.domains.length || parsed.urls.length
    );

    // Clear previous email's markers immediately when analysis changes/clears.
    setData({ markers: [], feed_status: {}, summary: { checked_indicators: 0 } });
    setError("");

    if (!hasIndicators) {
      setLoading(false);
      return undefined;
    }

    const controller = new AbortController();
    setLoading(true);

    fetch(`${resolvedApiBase}/api/intel/map-data`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed),
      signal: controller.signal,
    })
      .then(async (response) => {
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(
            payload.detail || `Map lookup failed with HTTP ${response.status}`
          );
        }

        const returnedMarkers = Array.isArray(payload.markers)
          ? payload.markers
          : [];

        const validMarkers = returnedMarkers
          .map((marker, index) => ({
            ...marker,
            latitude: Number(marker.latitude),
            longitude: Number(marker.longitude),
            id: marker.id || marker.ip || `current-email-marker-${index}`,
            is_case_marker: true,
            is_demo: false,
          }))
          .filter((marker) =>
            isValidCoordinate(marker.latitude, marker.longitude)
          );

        setData({
          ...payload,
          markers: validMarkers,
          feed_status:
            payload.feed_status && typeof payload.feed_status === "object"
              ? payload.feed_status
              : {},
        });
      })
      .catch((requestError) => {
        if (requestError.name !== "AbortError") {
          setData({ markers: [], feed_status: {} });
          setError(
            requestError.message || "FastAPI map lookup endpoint is unavailable."
          );
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
  }, [resolvedApiBase, signature]);

  const markers = data.markers || [];
  const threatCount = markers.filter((marker) => marker.threat_match).length;
  const feedEntries = Object.values(data.feed_status || {});
  const hasConnectedFeed = feedEntries.some(isConnectedFeedStatus);

  const feedLabel = loading
    ? "GEOIP LOOKUP IN PROGRESS"
    : hasConnectedFeed
      ? "INTELLIGENCE SOURCE CONNECTED"
      : markers.length
        ? "EMAIL-SPECIFIC GEO DATA"
        : "NO GEO DATA";

  const hasIndicators =
    indicators.ips.length || indicators.domains.length || indicators.urls.length;

  return (
    <div className="matsya-map-wrap">
      <div className="matsya-map-header">
        <div className="matsya-map-modes">
          <span className="matsya-map-mode-btn active">
            <MapPin size={13} />
            Current Email Investigation
          </span>
        </div>

        <div className="matsya-map-stats-strip">
          <span className="matsya-map-stat-badge">
            GEO NODES: <b>{markers.length}</b>
          </span>
          <span className="matsya-map-stat-badge">
            THREAT MATCHES: <b>{threatCount}</b>
          </span>
          <span
            className={`feed-indicator ${hasConnectedFeed ? "online" : "offline"}`}
            title="Connection status is based on the FastAPI response."
          >
            <span className="live-dot" />
            {feedLabel}
          </span>
        </div>
      </div>

      <MapContainer
        className="matsya-leaflet-map"
        center={[22, 15]}
        zoom={2}
        minZoom={2}
        maxZoom={12}
        scrollWheelZoom
        worldCopyJump
      >
        <TileLayer
          attribution="&copy; OpenStreetMap contributors"
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          maxZoom={19}
        />

        <FitMarkers markers={markers} />

        {markers.map((marker, index) => {
          const isThreat = Boolean(marker.threat_match);
          const markerId = marker.ip || marker.id || `geo-node-${index}`;

          return (
            <CircleMarker
              key={`${markerId}-${index}`}
              center={[marker.latitude, marker.longitude]}
              radius={9}
              pathOptions={{
                color: isThreat ? "#e11d48" : "#0891b2",
                fillColor: isThreat ? "#fb7185" : "#22d3ee",
                fillOpacity: 0.85,
                weight: 2,
              }}
            >
              <Popup>
                <div className="matsya-map-popup">
                  <div className="matsya-map-popup-header">
                    <code>{markerId}</code>
                    <span className="matsya-popup-tag case">
                      CURRENT EMAIL
                    </span>
                  </div>

                  <div className="matsya-map-popup-body">
                    <span>
                      <small>Approximate location:</small>
                      <b>
                        {[marker.city, marker.region, marker.country]
                          .filter(Boolean)
                          .join(", ") || "Location unavailable"}
                      </b>
                    </span>
                    <span>
                      <small>Data source:</small>
                      <span>{marker.geo_source || "Reported by backend"}</span>
                    </span>
                    {marker.threat_type && (
                      <span>
                        <small>Threat context:</small>
                        <b>{marker.threat_type}</b>
                      </span>
                    )}
                    {marker.abuse_confidence_score != null && (
                      <span>
                        <small>Abuse confidence score:</small>
                        <b>{marker.abuse_confidence_score}%</b>
                      </span>
                    )}
                  </div>

                  <div className="matsya-map-popup-footer">
                    {marker.ip ? (
                      <button
                        type="button"
                        onClick={() => {
                          if (typeof onInspectIp === "function") {
                            onInspectIp(marker.ip);
                          } else if (typeof onNavigate === "function") {
                            onNavigate("intel");
                          }
                        }}
                      >
                        Investigate IP in Threat Intel →
                      </button>
                    ) : null}
                    <span className="matsya-map-popup-disclaimer">
                      GeoIP is approximate and does not identify an individual.
                    </span>
                  </div>
                </div>
              </Popup>
            </CircleMarker>
          );
        })}
      </MapContainer>

      {loading && (
        <div className="matsya-map-message info">
          <RefreshCw size={14} className="rotating" />
          Looking up indicators extracted from the current email...
        </div>
      )}

      {!loading && !error && !hasIndicators && (
        <div className="matsya-map-message info">
          <ShieldAlert size={14} />
          No active email investigation. Upload and analyze an .eml file to
          display its extracted public IP geolocation. No sample markers are
          displayed.
        </div>
      )}

      {!loading && !error && hasIndicators && markers.length === 0 && (
        <div className="matsya-map-message info">
          <ShieldCheck size={14} />
          Indicators were extracted, but the configured backend returned no
          mappable coordinates. Private, reserved, or unresolvable IP addresses
          may not have a GeoIP location.
        </div>
      )}

      {error && (
        <div className="matsya-map-message error" role="alert">
          <span>Geolocation lookup failed: {error}. No demo markers are shown.</span>
          <button
            className="secondary-button"
            type="button"
            onClick={() => {
              if (typeof onNavigate === "function") onNavigate("upload");
            }}
          >
            Upload Evidence
          </button>
        </div>
      )}

      <div className="matsya-feed-footnote">
        <ShieldCheck size={13} />
        <span>
          OpenStreetMap basemap. Markers are rendered only from coordinates
          returned by the backend for the currently active email analysis.
          Synthetic demo locations and saved-case aggregation are disabled.
          GeoIP locations are approximate.
        </span>
      </div>
    </div>
  );
}
