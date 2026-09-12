import { InputHTMLAttributes, useId, useState } from "react";

interface Props extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  label: string;
  dark?: boolean;
}

/** Password field with a Show/Hide toggle. */
export default function PasswordInput({ label, dark = false, className, ...rest }: Props) {
  const [visible, setVisible] = useState(false);
  const id = useId();

  return (
    <div>
      <label htmlFor={id} className={dark ? "field-label-dark" : "field-label"}>
        {label}
      </label>
      <div className="relative">
        <input
          id={id}
          type={visible ? "text" : "password"}
          className={`${dark ? "input-dark" : "input"} pr-16 ${className ?? ""}`}
          {...rest}
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? "Hide password" : "Show password"}
          aria-pressed={visible}
          className={`absolute inset-y-0 right-0 px-3 font-mono text-[0.68rem] uppercase tracking-[0.08em] transition-colors ${
            dark ? "text-dim-dark hover:text-brand" : "text-dim hover:text-brand"
          }`}
        >
          {visible ? "Hide" : "Show"}
        </button>
      </div>
    </div>
  );
}
