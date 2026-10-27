//! FETCH_DATA ohne Windows: welcher Bereich geladen wird und wie er in
//! Stücken an Windows geht (CfExecute TRANSFER_DATA).
//!
//! Regeln der Cloud Files API: Offset auf 4 KiB ausgerichtet, Länge ein
//! Vielfaches von 4 KiB – außer das Stück endet am Dateiende. Windows nennt
//! einen Pflichtbereich (Required) und optional einen Vorauslese-Bereich; der
//! wird mitgeladen, wenn er anschließt. Geladen wird über HTTP Range in
//! Anfragen zu höchstens 32 MiB, an Windows geht es in Stücken zu 1 MiB.

use super::identity::Identity;
use super::remote::{ApiError, Remote};

pub const ALIGN: u64 = 4096;
pub const HTTP_CHUNK: u64 = 32 * 1024 * 1024;
pub const TRANSFER_CHUNK: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub identity: Option<Identity>,
    pub file_size: u64,
    pub required_offset: u64,
    pub required_length: u64,
    pub optional_offset: u64,
    pub optional_length: u64,
}

/// Ziel der geladenen Bytes (Windows: CfExecute TRANSFER_DATA + Fortschritt).
pub trait TransferSink {
    fn transfer(&mut self, offset: u64, data: &[u8]) -> Result<(), String>;
    fn progress(&mut self, total: u64, done: u64);
    /// Den Rest ab `offset` als fehlgeschlagen melden.
    fn fail(&mut self, offset: u64, length: u64);
    fn cancelled(&self) -> bool {
        false
    }
}

fn align_down(v: u64) -> u64 {
    v / ALIGN * ALIGN
}

fn align_up(v: u64) -> u64 {
    v.div_ceil(ALIGN) * ALIGN
}

/// Zu ladender Bereich `[start, end)`.
pub fn plan_range(r: &FetchRequest) -> (u64, u64) {
    let size = r.file_size;
    let start = align_down(r.required_offset).min(size);
    let req_end = r.required_offset.saturating_add(r.required_length);
    let mut end = align_up(req_end).min(size);
    if r.optional_length > 0 && r.optional_offset <= end {
        let opt_end = r.optional_offset.saturating_add(r.optional_length);
        if opt_end > end {
            end = align_up(opt_end).min(size);
        }
    }
    (start, end.max(start))
}

/// Lädt den Bereich und gibt ihn an `sink` → geladene Bytes.
pub fn fetch(remote: &dyn Remote, req: &FetchRequest, sink: &mut dyn TransferSink) -> Result<u64, ApiError> {
    let (start, end) = plan_range(req);
    match fetch_inner(remote, req, start, end, sink) {
        Ok(n) => Ok(n),
        Err((done, e)) => {
            let rest = end.saturating_sub(done);
            let (off, len) = if rest > 0 { (done, rest) } else { (align_down(req.required_offset), req.required_length.max(1)) };
            sink.fail(off, len);
            Err(e)
        }
    }
}

fn fetch_inner(remote: &dyn Remote, req: &FetchRequest, start: u64, end: u64, sink: &mut dyn TransferSink) -> Result<u64, (u64, ApiError)> {
    let id = req.identity.as_ref().ok_or((start, ApiError::new(None, "not_in_sync", "placeholder without identity")))?;
    let content = remote.content(id.node).map_err(|e| (start, e))?;
    let media = content.media_id.ok_or((start, ApiError::new(None, "bad_response", "no media")))?;
    if id.media.as_deref().is_some_and(|m| m != media) || content.size.is_some_and(|s| s != req.file_size) {
        // Der Server hat inzwischen eine andere Fassung: der Abgleich ersetzt den Platzhalter.
        return Err((start, ApiError::new(None, "not_in_sync", "newer version on the server")));
    }
    let total = end - start;
    let mut sent = start; // bis hier an Windows übergeben
    let mut buf: Vec<u8> = Vec::with_capacity(TRANSFER_CHUNK as usize);
    let mut pos = start;
    while pos < end {
        if sink.cancelled() {
            return Err((sent, ApiError::new(None, "cancelled", "cancelled")));
        }
        let to = (pos + HTTP_CHUNK).min(end);
        let mut sink_err: Option<String> = None;
        let res = {
            let mut on_data = |chunk: &[u8]| -> Result<(), String> {
                if sink.cancelled() {
                    return Err("cancelled".to_string());
                }
                let mut c = chunk;
                while !c.is_empty() {
                    let room = TRANSFER_CHUNK as usize - buf.len();
                    let take = room.min(c.len());
                    buf.extend_from_slice(&c[..take]);
                    c = &c[take..];
                    if buf.len() as u64 == TRANSFER_CHUNK {
                        if let Err(e) = sink.transfer(sent, &buf) {
                            sink_err = Some(e.clone());
                            return Err(e);
                        }
                        sent += buf.len() as u64;
                        buf.clear();
                        sink.progress(total, sent - start);
                    }
                }
                Ok(())
            };
            remote.download(&media, pos, to, &mut on_data)
        };
        match res {
            Ok(got) if got == to - pos => {}
            Ok(_) => return Err((sent, ApiError::network("short download"))),
            Err(e) => {
                let e = match sink_err {
                    Some(m) => ApiError::new(None, "transfer", m),
                    None => e,
                };
                return Err((sent, e));
            }
        }
        pos = to;
    }
    if !buf.is_empty() {
        sink.transfer(sent, &buf).map_err(|m| (sent, ApiError::new(None, "transfer", m)))?;
        sent += buf.len() as u64;
        sink.progress(total, sent - start);
    }
    Ok(sent - start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::Role;
    use crate::core::testing::FakeDrive;

    fn req(size: u64, off: u64, len: u64, oo: u64, ol: u64) -> FetchRequest {
        FetchRequest { identity: None, file_size: size, required_offset: off, required_length: len, optional_offset: oo, optional_length: ol }
    }

    #[test]
    fn ranges() {
        assert_eq!(plan_range(&req(10_000, 0, 10_000, 0, 0)), (0, 10_000));
        assert_eq!(plan_range(&req(100_000, 5000, 100, 0, 0)), (4096, 8192));
        assert_eq!(plan_range(&req(100_000, 5000, 100, 5100, 20_000)), (4096, 28_672));
        // Vorauslese-Bereich mit Lücke wird nicht geladen
        assert_eq!(plan_range(&req(100_000, 0, 4096, 50_000, 1000)), (0, 4096));
        assert_eq!(plan_range(&req(5000, 4096, 904, 0, 0)), (4096, 5000));
        assert_eq!(plan_range(&req(0, 0, 0, 0, 0)), (0, 0));
    }

    #[derive(Default)]
    struct Sink {
        parts: Vec<(u64, usize)>,
        data: Vec<u8>,
        failed: Option<(u64, u64)>,
        last_progress: (u64, u64),
        fail_at: Option<u64>,
    }

    impl TransferSink for Sink {
        fn transfer(&mut self, offset: u64, data: &[u8]) -> Result<(), String> {
            if self.fail_at == Some(offset) {
                return Err("boom".into());
            }
            self.parts.push((offset, data.len()));
            if self.data.len() < (offset as usize + data.len()) {
                self.data.resize(offset as usize + data.len(), 0);
            }
            self.data[offset as usize..offset as usize + data.len()].copy_from_slice(data);
            Ok(())
        }
        fn progress(&mut self, total: u64, done: u64) {
            self.last_progress = (total, done);
        }
        fn fail(&mut self, offset: u64, length: u64) {
            self.failed = Some((offset, length));
        }
    }

    fn setup(size: usize) -> (FakeDrive, Identity, Vec<u8>) {
        let d = FakeDrive::new();
        let root = d.add_area("mine:1", "Meine Dateien", Role::Manage);
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let n = d.add_file(root, "big.bin", &data);
        (d, Identity::new(n.id, n.rev, "mine:1", n.media_id.as_deref()), data)
    }

    #[test]
    fn whole_file_in_aligned_chunks() {
        let size = 2 * TRANSFER_CHUNK as usize + 12_345;
        let (d, id, data) = setup(size);
        let mut s = Sink::default();
        let r = FetchRequest { identity: Some(id), ..req(size as u64, 0, size as u64, 0, 0) };
        assert_eq!(fetch(&d, &r, &mut s).unwrap(), size as u64);
        assert_eq!(s.data, data);
        assert_eq!(s.parts.len(), 3);
        for (off, len) in &s.parts[..2] {
            assert_eq!(off % ALIGN, 0);
            assert_eq!(*len as u64 % ALIGN, 0);
        }
        assert_eq!(s.parts[2], (2 * TRANSFER_CHUNK, 12_345));
        assert_eq!(s.last_progress, (size as u64, size as u64));
        assert!(d.calls().contains(&"content".to_string()));
    }

    #[test]
    fn partial_range() {
        let (d, id, data) = setup(200_000);
        let mut s = Sink::default();
        let r = FetchRequest { identity: Some(id), ..req(200_000, 70_000, 10, 0, 0) };
        assert_eq!(fetch(&d, &r, &mut s).unwrap(), 4096);
        assert_eq!(s.parts, vec![(69_632, 4096)]);
        assert_eq!(&s.data[69_632..73_728], &data[69_632..73_728]);
    }

    #[test]
    fn newer_version_on_server_fails() {
        let (d, id, _) = setup(5000);
        d.modify(id.node, b"neu");
        let mut s = Sink::default();
        let r = FetchRequest { identity: Some(id), ..req(5000, 0, 5000, 0, 0) };
        assert_eq!(fetch(&d, &r, &mut s).unwrap_err().code, "not_in_sync");
        assert_eq!(s.failed, Some((0, 5000)));
    }

    #[test]
    fn transfer_error_reports_rest() {
        let size = 3 * TRANSFER_CHUNK as usize;
        let (d, id, _) = setup(size);
        let mut s = Sink { fail_at: Some(TRANSFER_CHUNK), ..Default::default() };
        let r = FetchRequest { identity: Some(id), ..req(size as u64, 0, size as u64, 0, 0) };
        assert_eq!(fetch(&d, &r, &mut s).unwrap_err().code, "transfer");
        assert_eq!(s.failed, Some((TRANSFER_CHUNK, 2 * TRANSFER_CHUNK)));
    }

    #[test]
    fn no_identity() {
        let (d, _, _) = setup(10);
        let mut s = Sink::default();
        assert_eq!(fetch(&d, &req(10, 0, 10, 0, 0), &mut s).unwrap_err().code, "not_in_sync");
    }
}
