import { NavLink } from "react-router-dom";
import { Shield, LayoutDashboard, Plus, List, Settings } from "lucide-react";

const nav = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scan/new", icon: Plus, label: "New Scan" },
  { to: "/scans", icon: List, label: "Scan History" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export default function Sidebar() {
  return (
    <aside className="w-60 min-h-screen bg-[#0A2342] flex flex-col">
      <div className="flex items-center gap-3 px-6 py-5 border-b border-white/10">
        <Shield className="text-[#E8651A]" size={28} />
        <span className="text-white font-bold text-lg tracking-wide">CLOUDWATCH</span>
      </div>
      <nav className="flex-1 py-4">
        {nav.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 px-6 py-3 text-sm font-medium transition-colors ${
                isActive
                  ? "bg-[#E8651A]/20 text-[#E8651A] border-r-2 border-[#E8651A]"
                  : "text-gray-300 hover:bg-white/5 hover:text-white"
              }`
            }
          >
            <Icon size={18} />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="px-6 py-4 text-xs text-gray-500 border-t border-white/10">
        AI-Powered CSPM v1.0
      </div>
    </aside>
  );
}
