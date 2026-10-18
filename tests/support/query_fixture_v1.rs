//! Independent PRXQDOC-NUL v1 frame writer for external gateway tests.

#[derive(Clone, Copy)]
pub enum Scalar<'a> {
    Null,
    Bool(bool),
    Negative(i64),
    Unsigned(u64),
    Text(&'a str),
}

pub fn frame(
    collection: &str,
    key: &str,
    attributes: &[(&str, Scalar<'_>)],
) -> Result<Vec<u8>, &'static str> {
    fn append_u16(out: &mut Vec<u8>, number: usize) -> Result<(), &'static str> {
        out.extend_from_slice(
            &u16::try_from(number)
                .map_err(|_| "length_u16")?
                .to_be_bytes(),
        );
        Ok(())
    }

    if !(1..=255).contains(&collection.len()) {
        return Err("collection_length");
    }
    if key.len() > 1024 || attributes.len() > 256 {
        return Err("fixture_count");
    }
    let mut canonical = attributes.to_vec();
    canonical.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    if canonical.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("duplicate_attribute");
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"PRXQDOC\0");
    out.extend_from_slice(&[0, 1, 0, 0]);
    out.extend_from_slice(&[0; 4]);
    append_u16(&mut out, collection.len())?;
    out.extend_from_slice(collection.as_bytes());
    append_u16(&mut out, key.len())?;
    out.extend_from_slice(key.as_bytes());
    append_u16(&mut out, canonical.len())?;
    for (name, value) in canonical {
        if !(1..=128).contains(&name.len()) {
            return Err("attribute_name_length");
        }
        append_u16(&mut out, name.len())?;
        out.extend_from_slice(name.as_bytes());
        match value {
            Scalar::Null => out.push(0),
            Scalar::Bool(false) => out.push(1),
            Scalar::Bool(true) => out.push(2),
            Scalar::Negative(number) => {
                if number >= 0 {
                    return Err("nonnegative_signed");
                }
                out.push(3);
                out.extend_from_slice(&number.to_be_bytes());
            }
            Scalar::Unsigned(number) => {
                out.push(4);
                out.extend_from_slice(&number.to_be_bytes());
            }
            Scalar::Text(text) => {
                if text.len() > 65_536 {
                    return Err("text_length");
                }
                out.push(5);
                out.extend_from_slice(
                    &u32::try_from(text.len())
                        .map_err(|_| "text_length")?
                        .to_be_bytes(),
                );
                out.extend_from_slice(text.as_bytes());
            }
        }
    }
    if out.len() > 1_048_576 {
        return Err("frame_length");
    }
    let total_len = u32::try_from(out.len()).map_err(|_| "frame_length")?;
    out[12..16].copy_from_slice(&total_len.to_be_bytes());
    Ok(out)
}
