use alkanes_runtime::runtime::AlkaneResponder;
use alkanes_runtime::{declare_alkane, message::MessageDispatch, token::Token};
use alkanes_support::response::CallResponse;
use alkanes_support::context::Context;
use anyhow::{anyhow, Result};
use bitcoin::{Transaction, Txid};
use metashrew_support::compat::to_arraybuffer_layout;
use metashrew_support::utils::consensus_decode;

pub struct ContextHandle(());

#[cfg(test)]
impl ContextHandle {
    pub fn transaction(&self) -> Vec<u8> {
        Vec::new()
    }
    
    pub fn block(&self) -> Vec<u8> {
        Vec::new()
    }
}

#[cfg(not(test))]
impl ContextHandle {
    pub fn transaction(&self) -> Vec<u8> {
        AlkaneResponder::transaction(self)
    }
    
    pub fn block(&self) -> Vec<u8> {
        AlkaneResponder::block(self)
    }
}

impl AlkaneResponder for ContextHandle {}

pub const CONTEXT: ContextHandle = ContextHandle(());

trait ContextExt {
    fn transaction_id(&self) -> Result<Txid>;
}

#[cfg(test)]
impl ContextExt for Context {
    fn transaction_id(&self) -> Result<Txid> {
        Ok(Txid::from_slice(&[0; 32]).unwrap_or_else(|_| {
            panic!("Failed to create zero Txid")
        }))
    }
}

#[cfg(not(test))]
impl ContextExt for Context {
    fn transaction_id(&self) -> Result<Txid> {
        Ok(
            consensus_decode::<Transaction>(&mut std::io::Cursor::new(CONTEXT.transaction()))?
                .compute_txid(),
        )
    }
}

#[derive(Default)]
pub struct Inugami(());

impl Token for Inugami {
    fn name(&self) -> String {
        String::from("Inugami")
    }
    
    fn symbol(&self) -> String {
        String::from("🩸")
    }
}

#[derive(MessageDispatch)]
enum InugamiMessage {
    #[opcode(0)]
    Initialize,

    #[opcode(100)]
    #[returns(String)]
    GetName,

    #[opcode(103)]
    #[returns(String)]
    BloodOath,
    
    #[opcode(105)]
    #[returns(u128)]
    SigilTrove,
    
    #[opcode(106)]
    #[returns(String)]
    BindSigil,
}

impl Inugami {
    fn message_key(&self, message: &[u8]) -> Vec<u8> {
        let mut key = b"/blood_sigil/".to_vec();
        let len = message.len() as u16;
        key.extend_from_slice(&len.to_le_bytes());
        key.extend_from_slice(message);
        key
    }

    pub fn get_coinbase_script_sig(&self, block_data: &[u8]) -> Result<Vec<u8>> {
        use std::io::{Cursor, Read};
        use bitcoin::consensus::{Decodable, encode::VarInt};

        const BLOCK_HEADER_SIZE: usize = 80;

        if block_data.len() < BLOCK_HEADER_SIZE + 1 {
            return Err(anyhow!("Block data too short"));
        }

        let mut cursor = Cursor::new(&block_data[BLOCK_HEADER_SIZE..]);

        let tx_count = VarInt::consensus_decode(&mut cursor)?;
        if tx_count.0 == 0 {
            return Err(anyhow!("Block does not contain transactions"));
        }

        let mut version = [0u8; 4];
        cursor.read_exact(&mut version)?;

        let mut marker_flag = [0u8; 2];
        cursor.read_exact(&mut marker_flag)?;
        let has_witness = marker_flag == [0x00, 0x01];

        if !has_witness {
            cursor.set_position(cursor.position() - 2);
        }

        let input_count = VarInt::consensus_decode(&mut cursor)?;
        if input_count.0 == 0 {
            return Err(anyhow!("Coinbase tx has no inputs"));
        }

        cursor.set_position(cursor.position() + 36);

        let script_len = VarInt::consensus_decode(&mut cursor)?;

        let mut script_sig = vec![0u8; script_len.0 as usize];
        cursor.read_exact(&mut script_sig)?;

        Ok(script_sig)
    }

    pub fn extract_message_from_coinbase(&self, block_data: &[u8], offset: usize, length: usize) -> Result<Vec<u8>> {
        let script = self.get_coinbase_script_sig(block_data)?;
        
        if offset >= script.len() {
            return Err(anyhow!("Offset {} exceeds script length {}", offset, script.len()));
        }
        
        if offset + length > script.len() {
            return Err(anyhow!("Message extends beyond script length: offset={}, length={}, script_len={}", 
                offset, length, script.len()));
        }
        
        Ok(script[offset..offset + length].to_vec())
    }

    fn blood_oath(&self) -> Result<CallResponse> {
        let context = self.context()?;

        if context.inputs.len() < 2 {
            return Err(anyhow!("Invalid calldata: need amount + message"));
        }

        let amount = context.inputs[1] as u128;
        if amount == 0 {
            return Err(anyhow!("Amount cannot be zero"));
        }

        let mut message_bytes: Vec<u8> = context.inputs[2..].iter()
            .map(|&b| b as u8).collect();

        while message_bytes.last() == Some(&0x00) {
            message_bytes.pop();
        }

        if message_bytes.is_empty() || message_bytes.len() > 200 {
            return Err(anyhow!("Message must be 1-200 bytes long"));
        }

        let _message_str = std::str::from_utf8(&message_bytes)
            .map_err(|_| anyhow!("Invalid UTF-8 message"))?;

        if context.incoming_alkanes.0.is_empty() {
            return Err(anyhow!("Must send at least one diesel for blood oath"));
        }

        let has_blood_token = context.incoming_alkanes.0.iter().any(|t| t.id.block == 2 && t.id.tx == 0);
        if !has_blood_token {
            return Err(anyhow!("At least one alkane must be diesel"));
        }

        let mut forwarded = context.incoming_alkanes.clone();
        let mut left = amount;
        for t in forwarded.0.iter_mut() {
            if t.id.block == 2 && t.id.tx == 0 && left > 0 {
                if t.value < left {
                    return Err(anyhow!("Not enough diesel sent: requested {}, available {}", amount, t.value));
                }
                t.value -= left;
                left = 0;
                break;
            }
        }
        if left > 0 {
            return Err(anyhow!("No appropriate diesel transfer found to withhold"));
        }
        forwarded.0.retain(|t| t.value > 0);

        let key = self.message_key(&message_bytes);
        let existing_bytes = self.load(key.clone());
        let mut existing = 0u128;
        if existing_bytes.len() == 16 {
            existing = u128::from_le_bytes(existing_bytes.try_into().unwrap());
        }
        let total = existing + amount;
        self.store(key, total.to_le_bytes().to_vec());

        let mut resp = CallResponse::forward(&forwarded);
        let msg_hex = message_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
        resp.data = format!("Blood Oath sealed | sigil=0x{} | held={} | total={}", msg_hex, amount, total).into_bytes();
        Ok(resp)
    }

    fn sigil_trove(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut resp = CallResponse::forward(&context.incoming_alkanes.clone());

        if context.inputs.len() < 2 {
            return Err(anyhow!("Invalid calldata: need message"));
        }

        let mut message_bytes: Vec<u8> = context.inputs[1..].iter()
            .map(|&b| b as u8).collect();

        while message_bytes.last() == Some(&0x00) {
            message_bytes.pop();
        }

        if message_bytes.is_empty() || message_bytes.len() > 200 {
            return Err(anyhow!("Message must be 1-200 bytes long"));
        }

        let key = self.message_key(&message_bytes);
        let existing_bytes = self.load(key);
        let stored = if existing_bytes.len() == 16 {
            u128::from_le_bytes(existing_bytes.try_into().unwrap())
        } else {
            0u128
        };
        resp.data = stored.to_le_bytes().to_vec();
        Ok(resp)
    }

    fn bind_sigil(&self) -> Result<CallResponse> {
        let context = self.context()?;
        
        if context.inputs.len() < 3 {
            return Err(anyhow!("Invalid calldata: need offset and length"));
        }

        let offset = context.inputs[1] as usize;
        let length = context.inputs[2] as usize;
        
        if length == 0 || length > 200 {
            return Err(anyhow!("Message length must be 1-200 bytes"));
        }

        let block_data = CONTEXT.block();
        let message_bytes = self.extract_message_from_coinbase(&block_data, offset, length)?;

        let _message_str = std::str::from_utf8(&message_bytes)
            .map_err(|_| anyhow!("Invalid UTF-8 message"))?;

        let key = self.message_key(&message_bytes);
        let existing_bytes = self.load(key.clone());
        
        let stored_amount = if existing_bytes.len() == 16 {
            u128::from_le_bytes(existing_bytes.try_into().unwrap())
        } else {
            0u128
        };

        if stored_amount == 0 {
            return Err(anyhow!("No diesel tokens stored for this sigil"));
        }

        let mut outgoing_alkanes = context.incoming_alkanes.clone();
        outgoing_alkanes.0.push(alkanes_support::parcel::AlkaneTransfer {
            id: alkanes_support::id::AlkaneId { block: 2, tx: 0 },
            value: stored_amount,
        });

        self.store(key, vec![]);

        let mut resp = CallResponse::forward(&outgoing_alkanes);
        let msg_hex = message_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
        resp.data = format!("Sigil bound | sigil=0x{} | claimed={}", msg_hex, stored_amount).into_bytes();
        
        Ok(resp)
    }

    fn initialize(&self) -> Result<CallResponse> {
        let init_key = "/initialized".as_bytes().to_vec();
        let init_bytes = self.load(init_key.clone());
        
        if init_bytes.len() > 0 {
            return Err(anyhow!("Contract already initialized"));
        }
        
        self.observe_initialization()?;
        let context = self.context()?;
        let response = CallResponse::forward(&context.incoming_alkanes.clone());

        Ok(response)
    }

    fn get_name(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes.clone());

        let name_key = "/name".as_bytes().to_vec();
        let name_bytes = self.load(name_key);
        
        if name_bytes.len() > 0 {
            response.data = name_bytes;
        } else {
            response.data = self.name().into_bytes().to_vec();
        }
        
        Ok(response)
    }

    fn get_symbol(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes.clone());

        let symbol_key = "/symbol".as_bytes().to_vec();
        let symbol_bytes = self.load(symbol_key);
        
        if symbol_bytes.len() > 0 {
            response.data = symbol_bytes;
        } else {
            response.data = self.symbol().into_bytes().to_vec();
        }
        
        Ok(response)
    }
}

impl AlkaneResponder for Inugami {}

declare_alkane! {
    impl AlkaneResponder for Inugami {
        type Message = InugamiMessage;
    }
}
