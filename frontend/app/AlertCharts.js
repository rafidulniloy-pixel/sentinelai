// AlertCharts.js
// =============================================================================
// Dashboard charts (MVP Feature 4: "Risk distribution / Charts")
//
// TWO CHARTS:
//   1. Doughnut - how alerts split across High / Medium / Low risk
//   2. Bar      - how many alerts of each attack type were found
//
// NOTE ON COLOURS: a canvas cannot read our CSS variables, so chart colours
// are written as plain hex values that match our dark theme.
// =============================================================================

"use client";

import { Doughnut, Bar } from "react-chartjs-2";
import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  Tooltip,
} from "chart.js";

// Chart.js is modular: we must register the pieces we actually use.
ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);

// Theme colours reused by both charts.
const COLOR_HIGH = "#ff3b6b";
const COLOR_MEDIUM = "#ffb020";
const COLOR_LOW = "#31d67f";
const COLOR_TEXT = "#8b97ad";
const COLOR_GRID = "rgba(130,165,225,0.12)";

export default function AlertCharts({ alerts }) {
  // Nothing to draw until detection has produced alerts.
  if (!alerts || alerts.length === 0) return null;

  // --- Chart 1 data: count alerts per risk level ---------------------------
  const high = alerts.filter((a) => a.risk_level === "High").length;
  const medium = alerts.filter((a) => a.risk_level === "Medium").length;
  const low = alerts.filter((a) => a.risk_level === "Low").length;

  const riskData = {
    labels: ["High", "Medium", "Low"],
    datasets: [
      {
        data: [high, medium, low],
        backgroundColor: [COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW],
        borderColor: "rgba(11,17,30,0.9)",   // dark gap between segments
        borderWidth: 3,
        hoverOffset: 6,
      },
    ],
  };

  // --- Chart 2 data: count alerts per attack type --------------------------
  // Build a { "Brute Force Attack": 3, "Port Scanning": 1, ... } tally.
  const tally = {};
  alerts.forEach((a) => {
    tally[a.attack_type] = (tally[a.attack_type] || 0) + 1;
  });
  const attackLabels = Object.keys(tally);
  const attackCounts = Object.values(tally);

  const attackData = {
    labels: attackLabels,
    datasets: [
      {
        label: "Alerts",
        data: attackCounts,
        backgroundColor: "#3b82f6",
        hoverBackgroundColor: "#7c5cff",
        borderRadius: 6,
        barThickness: 22,
      },
    ],
  };

  // --- Shared options ------------------------------------------------------
  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "62%",                       // makes it a ring, not a pie
    plugins: {
      legend: {
        position: "bottom",
        labels: { color: COLOR_TEXT, padding: 14, usePointStyle: true, font: { size: 12 } },
      },
    },
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: "y",                      // horizontal bars fit long attack names
    plugins: { legend: { display: false } },
    scales: {
      x: {
        ticks: { color: COLOR_TEXT, stepSize: 1, font: { size: 11 } },
        grid: { color: COLOR_GRID },
      },
      y: {
        ticks: { color: COLOR_TEXT, font: { size: 11 } },
        grid: { display: false },
      },
    },
  };

  return (
    <div className="chartrow">
      <div className="chartcard">
        <div className="charttitle">Risk distribution</div>
        <div className="chartbox">
          <Doughnut data={riskData} options={doughnutOptions} />
        </div>
      </div>

      <div className="chartcard">
        <div className="charttitle">Alerts by attack type</div>
        <div className="chartbox">
          <Bar data={attackData} options={barOptions} />
        </div>
      </div>
    </div>
  );
}