import { useCallback, useRef, useState } from "react";

export default function FileUpload({ onFiles }) {
  const [dragover, setDragover] = useState(false);
  const [selected, setSelected] = useState([]);
  const inputRef = useRef(null);

  const handleFiles = useCallback(
    (fileList) => {
      const arr = Array.from(fileList);
      setSelected(arr);
      onFiles(arr);
    },
    [onFiles]
  );

  const onDrop = useCallback(
    (e) => {
      e.preventDefault();
      setDragover(false);
      if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
    },
    [handleFiles]
  );

  return (
    <div>
      <div
        className={`drop-zone${dragover ? " dragover" : ""}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragover(true);
        }}
        onDragLeave={() => setDragover(false)}
        onDrop={onDrop}
      >
        <strong>Drop source files here</strong>
        <p>or click to browse</p>
        <input
          ref={inputRef}
          type="file"
          multiple
          style={{ display: "none" }}
          onChange={(e) => e.target.files && handleFiles(e.target.files)}
        />
      </div>
      {selected.length > 0 && (
        <div className="file-list">
          {selected.map((f, i) => (
            <span key={i}>{f.name}</span>
          ))}
        </div>
      )}
    </div>
  );
}
