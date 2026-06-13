// nrbf-parser - A high-performance MS-NRBF binary parser and encoder.
// Copyright (C) 2026  driedpampas@proton.me
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::error::{Error, Result};
use crate::records::*;
use std::collections::HashMap;
use std::io::Read;

/// A decoder for MS-NRBF binary streams.
pub struct Decoder<R: Read> {
    reader: R,
    metadata_registry: HashMap<i32, ClassInfoWithTypes>,
    /// Registry of libraries by ID.
    pub library_registry: HashMap<i32, String>,
    /// Current offset in the stream.
    pub offset: usize,
}

/// Metadata for a class including its types if available.
#[derive(Clone)]
pub struct ClassInfoWithTypes {
    pub class_info: ClassInfo,
    pub member_type_info: Option<MemberTypeInfo>,
    pub library_id: Option<i32>,
}

impl<R: Read> Decoder<R> {
    /// Creates a new decoder from a reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            metadata_registry: HashMap::new(),
            library_registry: HashMap::new(),
            offset: 0,
        }
    }

    /// Decodes the next record from the stream.
    ///
    /// Returns `Ok(Some(record))` if a record was successfully read,
    /// `Ok(None)` if the end of the stream was reached,
    /// or an `Err` if parsing failed.
    pub fn decode_next(&mut self) -> Result<Option<Record>> {
        let mut header = [0u8; 1];
        if self.reader.read_exact(&mut header).is_err() {
            return Ok(None);
        }
        self.offset += 1;

        let record_type = RecordType::try_from(header[0])?;
        match record_type {
            RecordType::SerializedStreamHeader => {
                let rec = self.read_serialization_header()?;
                Ok(Some(Record::SerializationHeader(rec)))
            }
            RecordType::BinaryLibrary => {
                let lib = self.read_binary_library()?;
                self.library_registry
                    .insert(lib.library_id, lib.library_name.clone());
                Ok(Some(Record::BinaryLibrary(lib)))
            }
            RecordType::ClassWithMembersAndTypes => {
                let rec = self.read_class_with_members_and_types()?;
                Ok(Some(Record::ClassWithMembersAndTypes(rec)))
            }
            RecordType::SystemClassWithMembersAndTypes => {
                let rec = self.read_system_class_with_members_and_types()?;
                Ok(Some(Record::SystemClassWithMembersAndTypes(rec)))
            }
            RecordType::SystemClassWithMembers => {
                let rec = self.read_system_class_with_members()?;
                Ok(Some(Record::SystemClassWithMembers(rec)))
            }
            RecordType::ClassWithMembers => {
                let rec = self.read_class_with_members()?;
                Ok(Some(Record::ClassWithMembers(rec)))
            }
            RecordType::ClassWithId => {
                let rec = self.read_class_with_id()?;
                Ok(Some(Record::ClassWithId(rec)))
            }
            RecordType::BinaryObjectString => {
                let object_id = self.read_i32()?;
                let value = self.read_length_prefixed_string()?;
                Ok(Some(Record::BinaryObjectString { object_id, value }))
            }
            RecordType::BinaryArray => {
                let rec = self.read_binary_array_full()?;
                Ok(Some(Record::BinaryArray(rec)))
            }
            RecordType::MemberPrimitiveTyped => {
                let pt = PrimitiveType::try_from(self.read_u8()?)?;
                let value = self.read_primitive_value(pt)?;
                Ok(Some(Record::MemberPrimitiveTyped {
                    primitive_type_enum: pt,
                    value,
                }))
            }
            RecordType::MemberReference => Ok(Some(Record::MemberReference {
                id_ref: self.read_i32()?,
            })),
            RecordType::ObjectNull => Ok(Some(Record::ObjectNull)),
            RecordType::ObjectNullMultiple256 => {
                Ok(Some(Record::ObjectNullMultiple256(ObjectNullMultiple256 {
                    null_count: self.read_u8()?,
                })))
            }
            RecordType::ObjectNullMultiple => {
                Ok(Some(Record::ObjectNullMultiple(ObjectNullMultiple {
                    null_count: self.read_i32()?,
                })))
            }
            RecordType::ArraySinglePrimitive => {
                let object_id = self.read_i32()?;
                let length = self.read_i32()?;
                let pt = PrimitiveType::try_from(self.read_u8()?)?;
                let mut values = Vec::with_capacity(length as usize);
                for _ in 0..length {
                    values.push(self.read_primitive_value(pt)?);
                }
                Ok(Some(Record::ArraySinglePrimitive(ArraySinglePrimitive {
                    object_id,
                    length,
                    primitive_type_enum: pt,
                    element_values: values,
                })))
            }
            RecordType::ArraySingleObject => {
                let object_id = self.read_i32()?;
                let length = self.read_i32()?;
                let values =
                    self.read_all_elements(length, BinaryType::Object, &AdditionalTypeInfo::None)?;
                Ok(Some(Record::ArraySingleObject(ArraySingleObject {
                    object_id,
                    length,
                    element_values: values,
                })))
            }
            RecordType::ArraySingleString => {
                let object_id = self.read_i32()?;
                let length = self.read_i32()?;
                let values =
                    self.read_all_elements(length, BinaryType::String, &AdditionalTypeInfo::None)?;
                Ok(Some(Record::ArraySingleString(ArraySingleString {
                    object_id,
                    length,
                    element_values: values,
                })))
            }
            RecordType::MessageEnd => Ok(Some(Record::MessageEnd)),
            _ => Err(Error::Custom(format!(
                "Unimplemented record type 0x{:02x}",
                header[0]
            ))),
        }
    }

    fn read_i32(&mut self) -> Result<i32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        self.offset += 4;
        Ok(i32::from_le_bytes(buf))
    }

    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.reader.read_exact(&mut buf)?;
        self.offset += 1;
        Ok(buf[0])
    }

    fn read_serialization_header(&mut self) -> Result<SerializationHeader> {
        Ok(SerializationHeader {
            root_id: self.read_i32()?,
            header_id: self.read_i32()?,
            major_version: self.read_i32()?,
            minor_version: self.read_i32()?,
        })
    }

    fn read_binary_library(&mut self) -> Result<BinaryLibrary> {
        Ok(BinaryLibrary {
            library_id: self.read_i32()?,
            library_name: self.read_length_prefixed_string()?,
        })
    }

    fn read_length_prefixed_string(&mut self) -> Result<String> {
        let length = self.read_variable_length_int()?;
        if length < 0 {
            return Err(Error::InvalidStringLength(length));
        }
        if length == 0 {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; length as usize];
        self.reader.read_exact(&mut buf)?;
        self.offset += length as usize;
        Ok(String::from_utf8(buf)?)
    }

    fn read_variable_length_int(&mut self) -> Result<i32> {
        let mut value: i32 = 0;
        let mut shift = 0;
        loop {
            let b = self.read_u8()?;
            value |= ((b & 0x7F) as i32) << shift;
            if (b & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift >= 35 {
                return Err(Error::Custom("Variable length int too long".into()));
            }
        }
        Ok(value)
    }

    fn read_class_info(&mut self) -> Result<ClassInfo> {
        let object_id = self.read_i32()?;
        let name = self.read_length_prefixed_string()?;
        let member_count = self.read_i32()?;
        let mut member_names = Vec::with_capacity(member_count as usize);
        for _ in 0..member_count {
            member_names.push(self.read_length_prefixed_string()?);
        }
        Ok(ClassInfo {
            object_id,
            name,
            member_count,
            member_names,
        })
    }

    fn read_member_type_info(&mut self, count: i32) -> Result<MemberTypeInfo> {
        let mut binary_type_enums = Vec::with_capacity(count as usize);
        for _ in 0..count {
            binary_type_enums.push(BinaryType::try_from(self.read_u8()?)?);
        }

        let mut additional_infos = Vec::with_capacity(count as usize);
        for i in 0..count {
            let bt = binary_type_enums[i as usize];
            let info = match bt {
                BinaryType::Primitive | BinaryType::PrimitiveArray => {
                    AdditionalTypeInfo::Primitive(PrimitiveType::try_from(self.read_u8()?)?)
                }
                BinaryType::SystemClass => {
                    AdditionalTypeInfo::SystemClass(self.read_length_prefixed_string()?)
                }
                BinaryType::Class => AdditionalTypeInfo::Class(ClassTypeInfo {
                    type_name: self.read_length_prefixed_string()?,
                    library_id: self.read_i32()?,
                }),
                _ => AdditionalTypeInfo::None,
            };
            additional_infos.push(info);
        }

        Ok(MemberTypeInfo {
            binary_type_enums,
            additional_infos,
        })
    }

    fn read_class_with_members_and_types(&mut self) -> Result<ClassWithMembersAndTypes> {
        let class_info = self.read_class_info()?;
        let member_type_info = self.read_member_type_info(class_info.member_count)?;
        let library_id = self.read_i32()?;

        self.metadata_registry.insert(
            class_info.object_id,
            ClassInfoWithTypes {
                class_info: class_info.clone(),
                member_type_info: Some(member_type_info.clone()),
                library_id: Some(library_id),
            },
        );

        let member_values =
            self.read_all_member_values(&class_info, &Some(member_type_info.clone()))?;
        Ok(ClassWithMembersAndTypes {
            class_info,
            member_type_info,
            library_id,
            member_values,
        })
    }

    fn read_system_class_with_members_and_types(
        &mut self,
    ) -> Result<SystemClassWithMembersAndTypes> {
        let class_info = self.read_class_info()?;
        let member_type_info = self.read_member_type_info(class_info.member_count)?;

        self.metadata_registry.insert(
            class_info.object_id,
            ClassInfoWithTypes {
                class_info: class_info.clone(),
                member_type_info: Some(member_type_info.clone()),
                library_id: None,
            },
        );

        let member_values =
            self.read_all_member_values(&class_info, &Some(member_type_info.clone()))?;
        Ok(SystemClassWithMembersAndTypes {
            class_info,
            member_type_info,
            member_values,
        })
    }

    fn read_system_class_with_members(&mut self) -> Result<SystemClassWithMembers> {
        let class_info = self.read_class_info()?;

        self.metadata_registry.insert(
            class_info.object_id,
            ClassInfoWithTypes {
                class_info: class_info.clone(),
                member_type_info: None,
                library_id: None,
            },
        );

        let member_values = self.read_all_member_values(&class_info, &None)?;
        Ok(SystemClassWithMembers {
            class_info,
            member_values,
        })
    }

    fn read_class_with_members(&mut self) -> Result<ClassWithMembers> {
        let class_info = self.read_class_info()?;
        let library_id = self.read_i32()?;

        self.metadata_registry.insert(
            class_info.object_id,
            ClassInfoWithTypes {
                class_info: class_info.clone(),
                member_type_info: None,
                library_id: Some(library_id),
            },
        );

        let member_values = self.read_all_member_values(&class_info, &None)?;
        Ok(ClassWithMembers {
            class_info,
            library_id,
            member_values,
        })
    }

    fn read_class_with_id(&mut self) -> Result<ClassWithId> {
        let object_id = self.read_i32()?;
        let metadata_id = self.read_i32()?;

        let meta = self
            .metadata_registry
            .get(&metadata_id)
            .ok_or_else(|| Error::Custom(format!("Metadata ID {} not found", metadata_id)))?
            .clone();

        let member_values =
            self.read_all_member_values(&meta.class_info, &meta.member_type_info)?;

        Ok(ClassWithId {
            object_id,
            metadata_id,
            member_values,
        })
    }

    fn read_binary_array_full(&mut self) -> Result<BinaryArray> {
        let object_id = self.read_i32()?;
        let binary_array_type_enum = self.read_u8()?;
        let rank = self.read_i32()?;
        let mut lengths = Vec::with_capacity(rank as usize);
        for _ in 0..rank {
            lengths.push(self.read_i32()?);
        }

        let mut lower_bounds = None;
        if binary_array_type_enum == 3 || binary_array_type_enum == 4 || binary_array_type_enum == 5
        {
            let mut bounds = Vec::with_capacity(rank as usize);
            for _ in 0..rank {
                bounds.push(self.read_i32()?);
            }
            lower_bounds = Some(bounds);
        }

        let type_enum = BinaryType::try_from(self.read_u8()?)?;
        let additional_type_info = match type_enum {
            BinaryType::Primitive => {
                AdditionalTypeInfo::Primitive(PrimitiveType::try_from(self.read_u8()?)?)
            }
            BinaryType::SystemClass => {
                AdditionalTypeInfo::SystemClass(self.read_length_prefixed_string()?)
            }
            BinaryType::Class => AdditionalTypeInfo::Class(ClassTypeInfo {
                type_name: self.read_length_prefixed_string()?,
                library_id: self.read_i32()?,
            }),
            _ => AdditionalTypeInfo::None,
        };

        let total_elements: i32 = lengths.iter().product();
        let element_values =
            self.read_all_elements(total_elements, type_enum, &additional_type_info)?;

        Ok(BinaryArray {
            object_id,
            binary_array_type_enum,
            rank,
            lengths,
            lower_bounds,
            type_enum,
            additional_type_info,
            element_values,
        })
    }

    fn read_primitive_value(&mut self, pt: PrimitiveType) -> Result<PrimitiveValue> {
        match pt {
            PrimitiveType::Boolean => Ok(PrimitiveValue::Boolean(self.read_u8()? != 0)),
            PrimitiveType::Byte => Ok(PrimitiveValue::Byte(self.read_u8()?)),
            PrimitiveType::Char => {
                let b = self.read_u8()?;
                Ok(PrimitiveValue::Char(b as char))
            }
            PrimitiveType::Int16 => {
                let mut buf = [0u8; 2];
                self.reader.read_exact(&mut buf)?;
                self.offset += 2;
                Ok(PrimitiveValue::Int16(i16::from_le_bytes(buf)))
            }
            PrimitiveType::Int32 => Ok(PrimitiveValue::Int32(self.read_i32()?)),
            PrimitiveType::Int64 => {
                let mut buf = [0u8; 8];
                self.reader.read_exact(&mut buf)?;
                self.offset += 8;
                Ok(PrimitiveValue::Int64(i64::from_le_bytes(buf)))
            }
            PrimitiveType::TimeSpan => {
                let mut buf = [0u8; 8];
                self.reader.read_exact(&mut buf)?;
                self.offset += 8;
                Ok(PrimitiveValue::TimeSpan(i64::from_le_bytes(buf)))
            }
            PrimitiveType::DateTime => {
                let mut buf = [0u8; 8];
                self.reader.read_exact(&mut buf)?;
                self.offset += 8;
                Ok(PrimitiveValue::DateTime(u64::from_le_bytes(buf)))
            }
            PrimitiveType::SByte => Ok(PrimitiveValue::SByte(self.read_u8()? as i8)),
            PrimitiveType::Single => {
                let mut buf = [0u8; 4];
                self.reader.read_exact(&mut buf)?;
                self.offset += 4;
                Ok(PrimitiveValue::Single(f32::from_le_bytes(buf)))
            }
            PrimitiveType::Double => {
                let mut buf = [0u8; 8];
                self.reader.read_exact(&mut buf)?;
                self.offset += 8;
                Ok(PrimitiveValue::Double(f64::from_le_bytes(buf)))
            }
            PrimitiveType::Decimal => {
                let mut buf = [0u8; 16];
                self.reader.read_exact(&mut buf)?;
                self.offset += 16;
                // Represent as a hex string or just raw bytes for now since we don't have a 128-bit decimal type easily
                Ok(PrimitiveValue::Decimal(hex::encode(buf)))
            }
            PrimitiveType::UInt16 => {
                let mut buf = [0u8; 2];
                self.reader.read_exact(&mut buf)?;
                self.offset += 2;
                Ok(PrimitiveValue::UInt16(u16::from_le_bytes(buf)))
            }
            PrimitiveType::UInt32 => {
                let mut buf = [0u8; 4];
                self.reader.read_exact(&mut buf)?;
                self.offset += 4;
                Ok(PrimitiveValue::UInt32(u32::from_le_bytes(buf)))
            }
            PrimitiveType::UInt64 => {
                let mut buf = [0u8; 8];
                self.reader.read_exact(&mut buf)?;
                self.offset += 8;
                Ok(PrimitiveValue::UInt64(u64::from_le_bytes(buf)))
            }
            PrimitiveType::String => {
                Ok(PrimitiveValue::String(self.read_length_prefixed_string()?))
            }
            PrimitiveType::Null => Ok(PrimitiveValue::Null),
        }
    }

    fn read_object_value(
        &mut self,
        bt: BinaryType,
        add_info: &AdditionalTypeInfo,
    ) -> Result<ObjectValue> {
        match bt {
            BinaryType::Primitive => {
                if let AdditionalTypeInfo::Primitive(pt) = add_info {
                    Ok(ObjectValue::Primitive(self.read_primitive_value(*pt)?))
                } else {
                    Err(Error::Custom("Expected primitive type info".into()))
                }
            }
            _ => {
                if let Some(record) = self.decode_next()? {
                    Ok(ObjectValue::Record(Box::new(record)))
                } else {
                    Err(Error::Custom("Expected record for object value".into()))
                }
            }
        }
    }

    fn read_all_member_values(
        &mut self,
        class_info: &ClassInfo,
        member_type_info: &Option<MemberTypeInfo>,
    ) -> Result<Vec<ObjectValue>> {
        let mut values = Vec::with_capacity(class_info.member_count as usize);
        for i in 0..class_info.member_count {
            if let Some(mti) = member_type_info {
                let bt = mti.binary_type_enums[i as usize];
                let add_info = &mti.additional_infos[i as usize];
                values.push(self.read_object_value(bt, add_info)?);
            } else if let Some(record) = self.decode_next()? {
                values.push(ObjectValue::Record(Box::new(record)));
            } else {
                return Err(Error::Custom("Expected record for member value".into()));
            }
        }
        Ok(values)
    }

    fn read_all_elements(
        &mut self,
        count: i32,
        bt: BinaryType,
        add_info: &AdditionalTypeInfo,
    ) -> Result<Vec<ObjectValue>> {
        let mut values = Vec::with_capacity(count as usize);
        let mut i = 0;
        while i < count {
            let val = self.read_object_value(bt, add_info)?;
            match &val {
                ObjectValue::Record(r) => match r.as_ref() {
                    Record::ObjectNullMultiple(n) => {
                        for _ in 0..n.null_count {
                            values.push(ObjectValue::Primitive(PrimitiveValue::Null));
                            i += 1;
                        }
                        continue;
                    }
                    Record::ObjectNullMultiple256(n) => {
                        for _ in 0..n.null_count {
                            values.push(ObjectValue::Primitive(PrimitiveValue::Null));
                            i += 1;
                        }
                        continue;
                    }
                    Record::ObjectNull => {
                        values.push(ObjectValue::Primitive(PrimitiveValue::Null));
                    }
                    _ => {
                        values.push(val);
                    }
                },
                _ => {
                    values.push(val);
                }
            }
            i += 1;
        }
        Ok(values)
    }
}
