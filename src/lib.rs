use alkanes_runtime::runtime::AlkaneResponder;
use alkanes_runtime::{declare_alkane, message::MessageDispatch, token::Token};
use alkanes_runtime::storage::StoragePointer;
use alkanes_support::response::CallResponse;
use anyhow::{anyhow, Result};
use metashrew_support::compat::to_arraybuffer_layout;
use metashrew_support::index_pointer::KeyValuePointer;

mod svg_generator;
use svg_generator::InugamiSvgGenerator;

// Alkane ID constants
const DIESEL_BLOCK: u128 = 2;
const DIESEL_TX: u128 = 0;

// Transformation constants
const COOLDOWN_BLOCKS: u64 = 144;

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

    #[opcode(99)]
    #[returns(String)]
    GetName,

    #[opcode(100)]
    #[returns(String)]
    GetSymbol,

    #[opcode(444)]
    #[returns(String)]
    BloodOath,
    
    #[opcode(404)]
    #[returns(u128)]
    SigilTrove,
    
    #[opcode(4242)]
    #[returns(String)]
    BindSigil,

    #[opcode(1000)]
    #[returns(Vec<u8>)]
    GetData,

    #[opcode(1001)]
    #[returns(String)]
    SoulTransform {
        emoji: u128,
        color: u128,
    },
}

impl Inugami {
    fn emoji_key(&self) -> Vec<u8> {
        "/current_emoji".as_bytes().to_vec()
    }

    fn bg_color_key(&self) -> Vec<u8> {
        "/bg_color".as_bytes().to_vec()
    }

    fn get_current_emoji(&self) -> String {
        let emoji_bytes = self.load(self.emoji_key());
        if emoji_bytes.is_empty() {
            "🩸".to_string()
        } else {
            String::from_utf8(emoji_bytes).unwrap_or("🩸".to_string())
        }
    }

    fn get_current_bg_color(&self) -> String {
        let color_bytes = self.load(self.bg_color_key());
        if color_bytes.is_empty() {
            "#000000".to_string()
        } else {
            String::from_utf8(color_bytes).unwrap_or("#000000".to_string())
        }
    }

    fn set_current_emoji(&self, emoji: &str) {
        self.store(self.emoji_key(), emoji.as_bytes().to_vec());
    }

    fn set_current_bg_color(&self, color: &str) {
        self.store(self.bg_color_key(), color.as_bytes().to_vec());
    }

    fn last_transform_key(&self) -> Vec<u8> {
        "/last_transform_block".as_bytes().to_vec()
    }

    fn get_last_transform_block(&self) -> u64 {
        let bytes = self.load(self.last_transform_key());
        if bytes.len() == 8 {
            let array: [u8; 8] = match bytes.try_into() {
                Ok(arr) => arr,
                Err(_) => return 0,
            };
            u64::from_le_bytes(array)
        } else {
            0
        }
    }

    fn set_last_transform_block(&self, block: u64) {
        self.store(self.last_transform_key(), block.to_le_bytes().to_vec());
    }

    fn can_transform(&self) -> Result<()> {
        let current_height = self.height();
        let last_transform = self.get_last_transform_block();
        
        if last_transform == 0 {
            return Ok(());
        }
        
        let blocks_since_transform = current_height.checked_sub(last_transform)
             .ok_or_else(|| anyhow!("Height calculation error"))?;
             
         if blocks_since_transform < COOLDOWN_BLOCKS {
             return Err(anyhow!("Soul transformation locked. {} blocks remaining", 
                 COOLDOWN_BLOCKS - blocks_since_transform));
         }
        
        Ok(())
    }

    fn observe_transform(&self) -> Result<()> {
        let block_header = self.block_header()?;
        let block_hash = block_header.block_hash();
        let hash_bytes: &[u8] = block_hash.as_ref();
        let mut p = StoragePointer::from_keyword("/transform/").select(&hash_bytes.to_vec());

        if p.get().is_empty() {
            p.set_value::<u8>(1);
            Ok(())
        } else {
            Err(anyhow!("Soul transformation already performed in block {} (hash: {})", 
                self.height(), block_hash))
        }
    }

    pub fn message_key(&self, message: &[u8]) -> Vec<u8> {
        let mut key = b"/blood_sigil/".to_vec();
        let len = message.len() as u16;
        key.extend_from_slice(&len.to_le_bytes());
        key.extend_from_slice(message);
        key
    }

    pub fn get_coinbase_script_sig(&self) -> Result<Vec<u8>> {
        let tx = self.coinbase_tx()?;

        if tx.input.is_empty() {
            return Err(anyhow!("Coinbase transaction has no inputs"));
        }

        Ok(tx.input[0].script_sig.as_bytes().to_vec())
    }

    pub fn extract_message_from_coinbase(&self, offset: usize, length: usize) -> Result<Vec<u8>> {
        let script = self.get_coinbase_script_sig()?;
        
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

        if context.inputs.len() < 3 {
            return Err(anyhow!("Invalid calldata: need amount, msg_len, message"));
        }

        let amount = context.inputs[1] as u128;

        if amount == 0 {
            return Err(anyhow!("Amount cannot be zero"));
        }

        let msg_len = context.inputs[2] as usize;
        if msg_len == 0 || msg_len > 200 {
            return Err(anyhow!("Message length must be 1-200 bytes"));
        }

        if context.inputs.len() < 3 + msg_len {
            return Err(anyhow!("Invalid calldata: message length mismatch"));
        }

        let message_bytes: Vec<u8> = context.inputs[3..3+msg_len].iter()
            .map(|&b| b as u8).collect();

        let _message_str = std::str::from_utf8(&message_bytes)
            .map_err(|_| anyhow!("Invalid UTF-8 message"))?;

        if context.incoming_alkanes.0.is_empty() {
            return Err(anyhow!("Must send at least one diesel for blood oath"));
        }

        let has_blood_token = context.incoming_alkanes.0.iter().any(|t| t.id.block == DIESEL_BLOCK && t.id.tx == DIESEL_TX);
        if !has_blood_token {
            return Err(anyhow!("At least one alkane must be diesel"));
        }

        let mut forwarded = context.incoming_alkanes.clone();
        let mut left = amount;
        for t in forwarded.0.iter_mut() {
            if t.id.block == DIESEL_BLOCK && t.id.tx == DIESEL_TX && left > 0 {
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
        let total = existing.checked_add(amount)
            .ok_or_else(|| anyhow!("Amount overflow"))?;
        self.store(key, total.to_le_bytes().to_vec());

        let mut response = CallResponse::forward(&forwarded);
        let msg_hex = message_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
        response.data = format!("Blood Oath sealed | sigil=0x{} | held={} | total={}", msg_hex, amount, total).into_bytes();
        Ok(response)
    }

    fn sigil_trove(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes.clone());

        if context.inputs.len() < 2 {
            return Err(anyhow!("Invalid calldata: need message"));
        }

        let message_bytes: Vec<u8> = context.inputs[1..].iter()
            .map(|&b| b as u8).collect();

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
        response.data = stored.to_le_bytes().to_vec();
        Ok(response)
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

        let message_bytes = self.extract_message_from_coinbase(offset, length)?;

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
            id: alkanes_support::id::AlkaneId { block: DIESEL_BLOCK, tx: DIESEL_TX },
            value: stored_amount,
        });

        self.store(key, vec![]);

        let mut response = CallResponse::forward(&outgoing_alkanes);
        let msg_hex = message_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
        response.data = format!("Sigil bound | sigil=0x{} | claimed={}", msg_hex, stored_amount).into_bytes();
        
        Ok(response)
    }

    fn initialize(&self) -> Result<CallResponse> {
        self.observe_initialization()?;
        let context = self.context()?;

        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.alkanes.0.push(alkanes_support::parcel::AlkaneTransfer {
            id: context.myself.clone(),
            value: 100000u128,
        });

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

    fn get_data(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes.clone());
        
        let emoji = self.get_current_emoji();
        let bg_color = self.get_current_bg_color();
        
        let svg = InugamiSvgGenerator::generate_svg_with_emoji_and_color(&emoji, &bg_color)?;
        response.data = svg.as_bytes().to_vec();
        
        Ok(response)
    }

    fn soul_transform(&self, emoji: u128, color: u128) -> Result<CallResponse> {
          let context = self.context()?;
          
          self.can_transform()?;
          
          let fee_amount = 1u128;
          
          // 1) Dry check for fee without mutating response
          let has_fee = context.incoming_alkanes.0.iter()
              .any(|t| t.id == context.myself && t.value >= fee_amount);
          if !has_fee {
              return Err(anyhow!("Must send at least {} Inugami tokens for soul transformation", fee_amount));
          }
          
          // 2) Mark block as used - no data mutations yet
          self.observe_transform()?;
          
          // 3) Now safely change state - transformation is guaranteed at this point
          let new_emoji = InugamiSvgGenerator::get_emoji_by_index(emoji as usize)
              .unwrap_or_else(|_| "🩸".to_string());
          self.set_current_emoji(&new_emoji);
          
          let new_color = format!("#{:06X}", color & 0xFFFFFF);
          self.set_current_bg_color(&new_color);
          
          self.set_last_transform_block(self.height());
          
          // 4) Finally create response and deduct fee
          let mut response = CallResponse::forward(&context.incoming_alkanes);
          response.alkanes.0.iter_mut()
              .find(|t| t.id == context.myself && t.value >= fee_amount)
              .map(|t| t.value -= fee_amount);
          response.alkanes.0.retain(|t| t.value > 0);
          
          let response_msg = format!("Soul transformed to: {} with color: {} (fee: {} tokens)", 
              new_emoji, new_color, fee_amount);
          response.data = response_msg.into_bytes();
          Ok(response)
      }
}

impl AlkaneResponder for Inugami {}

declare_alkane! {
    impl AlkaneResponder for Inugami {
        type Message = InugamiMessage;
    }
}

