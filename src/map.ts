import ForceGraph3D from '3d-force-graph';
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// Colors
const COLOR_ROUTER = "#ff00ff"; // Gateway (Magenta)
const COLOR_DEVICE = "#00ccff"; // Standard (Cyan)
// const COLOR_THREAT = "#ff3333"; // Attacker (Red) - Future Use
const COLOR_LINK = "rgba(0, 255, 136, 0.2)";

// Graph Data
const gData = {
    nodes: [{ id: 'router', ip: 'GATEWAY', color: COLOR_ROUTER, val: 20 }] as any[],
    links: [] as any[]
};

// Init Graph
// @ts-ignore
const Graph = ForceGraph3D()
    (document.getElementById('graph-container')!)
    .graphData(gData)
    .nodeAutoColorBy('group')
    .nodeColor((node: any) => node.color || COLOR_DEVICE)
    .linkColor(() => COLOR_LINK)
    .nodeLabel('ip')
    .popupBackground('#050505')
    .nodeResolution(16)
    .linkWidth(1)
    .linkOpacity(0.5);

// State
const devices = new Set<string>();
devices.add('GATEWAY'); // Helper to prevent duplicate router

async function init() {
    console.log("Initializing Map...");
    const status = document.getElementById('status-text');

    try {
        // 1. Load Initial Devices
        const initialDevices = await invoke("get_devices") as any[];
        console.log("Loaded devices:", initialDevices);

        initialDevices.forEach(d => addNode(d));

        status!.innerText = `Monitoring ${gData.nodes.length} Nodes`;

        // 2. Listen for New Devices
        await listen("new-device", (e: any) => {
            addNode(e.payload);
            status!.innerText = `Monitoring ${gData.nodes.length} Nodes`;
        });

        // 3. Listen for Threats (Visual FX)
        await listen("threat-alert", (_e: any) => {
            // e.payload is string message which might contain source IP
            // Ideally backend sends structured event, but we parse for now or just shake the graph
            shakeGraph();
        });

    } catch (e) {
        console.error(e);
        console.error(e);
        status!.innerText = "Connection Error (Check Console)";
        status!.style.color = "red";
    }
}

function addNode(device: any) {
    if (devices.has(device.ip)) return;
    devices.add(device.ip);

    // Node
    gData.nodes.push({
        id: device.ip,
        ip: device.ip,
        mac: device.mac,
        vendor: device.manufacturer || "Unknown",
        color: COLOR_DEVICE,
        val: 5
    });

    // Link to Router (Star Topology for now)
    gData.links.push({
        source: 'router',
        target: device.ip
    });

    Graph.graphData(gData);
}

function shakeGraph() {
    // Simple visual feedback
    const originalColor = Graph.backgroundColor();
    Graph.backgroundColor('#1a0505'); // Flash red background slightly
    setTimeout(() => Graph.backgroundColor(originalColor), 200);
}

document.addEventListener("DOMContentLoaded", init);
