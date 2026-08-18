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

// Theme colours (a canvas cannot read CSS variables, so these are plain hex).
const COLOR_HIGH = "#ff3b6b";
const COLOR_MEDIUM = "#ffb020";
const COLOR_LOW = "#31d67f";
const COLOR_TEXT = "#8b97ad";
const COLOR_GRID = "rgba(130,165,225,0.12)";

export default function AlertCharts({ alerts }) {
  // Nothing to draw until detection has produced alerts.
  if (!alerts || alerts.length === 0) return null;

  // --- Chart 1: count alerts per risk level --------------------------------
  const high = alerts.filter((a) => a.risk_level === "High").length;
  const medium = alerts.filter((a) => a.risk_level === "Medium").length;
  const low = alerts.filter((a) => a.risk_level === "Low").length;

  const riskData = {
    labels: ["High", "Medium", "Low"],
    datasets: [
      {
        data: [high, medium, low],
        backgroundColor: [COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW],
        borderColor: "rgba(11,17,30,0.9)",
        borderWidth: 3,
        hoverOffset: 6,
      },
    ],
  };

  // --- Chart 2: count alerts per attack type -------------------------------
  const tally = {};
  alerts.forEach((a) => {
    tally[a.attack_type] = (tally[a.attack_type] || 0) + 1;
  });

  const attackData = {
    labels: Object.keys(tally),
    datasets: [
      {
        label: "Alerts",
        data: Object.values(tally),
        backgroundColor: "#3b82f6",
        hoverBackgroundColor: "#7c5cff",
        borderRadius: 6,
        barThickness: 22,
      },
    ],
  };

  // --- Chart options -------------------------------------------------------
  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "62%",
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
    indexAxis: "y",
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