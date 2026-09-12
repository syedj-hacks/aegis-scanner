import { Link } from "react-router-dom";

export default function Brand({ to = "/" }: { to?: string }) {
  return (
    <Link to={to} className="brand-mark text-on-dark">
      Aegis Shield<span className="text-brand">.</span>
    </Link>
  );
}
