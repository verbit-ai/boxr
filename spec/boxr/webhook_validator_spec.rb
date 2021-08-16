# frozen_string_literal: true

def generate_signature(payload, timestamp, key)
  message_as_bytes = (payload.bytes + timestamp.bytes).pack('U*')
  digest = OpenSSL::HMAC.digest('SHA256', key, message_as_bytes)
  Base64.strict_encode64(digest)
end

# rake spec SPEC_OPTS="-e \"Boxr::WebhookValidator"\"
describe Boxr::WebhookValidator, :skip_reset do
  subject(:validator) do
    described_class.new(
      payload,
      timestamp: timestamp,
      primary_signature: primary_signature,
      secondary_signature: secondary_signature,
      primary_signature_key: primary_signature_key,
      secondary_signature_key: secondary_signature_key
    )
  end

  let(:payload) { {hello: 'world'}.to_json }
  let(:timestamp) { (Time.now.utc - 60).to_s }
  let(:primary_signature_key) { ENV['BOX_PRIMARY_SIGNATURE_KEY'].to_s }
  let(:secondary_signature_key) { ENV['BOX_SECONDARY_SIGNATURE_KEY'].to_s }
  let(:primary_signature) { nil }
  let(:secondary_signature) { nil }

  describe '#verify_delivery_timestamp' do
    subject { validator.verify_delivery_timestamp }

    context 'maximum age is under 10 minutes' do
      let(:timestamp) { (Time.now.utc - 300).to_s } # 5 minutes (in seconds)

      it 'returns true' do
        expect(subject).to eq(true)
      end
    end

    context 'maximum age is over 10 minute' do
      let(:timestamp) { (Time.now.utc - 660).to_s } # 11 minutes (in seconds)

      it 'returns false' do
        expect(subject).to eq(false)
      end
    end

    context 'no delivery timestamp is supplied' do
      let(:timestamp) { nil }

      it 'raises an error' do
        expect do
          subject
        end.to raise_error(Boxr::BoxrError, 'Webhook authenticity not verified: invalid timestamp')
      end
    end

    context 'bogus timestamp is supplied' do
      let(:timestamp) { 'hello I am invalid' }

      it 'raises an error' do
        expect do
          subject
        end.to raise_error(Boxr::BoxrError, 'Webhook authenticity not verified: invalid timestamp')
      end
    end
  end

  describe '#verify_signature' do
    subject { validator.verify_signature }

    let(:payload) { 'some data' }

    let(:timestamp) { (Time.now.utc - 300).to_s } # 5 minutes ago (in seconds)

    let(:primary_signature) { generate_signature(payload, timestamp, primary_signature_key.to_s) }
    let(:secondary_signature) { generate_signature(payload, timestamp, secondary_signature_key.to_s) }

    context 'valid primary key' do
      it 'returns true' do
        expect(subject).to eq(true)
      end
    end

    context 'invalid primary key, valid secondary key' do
      let(:primary_signature) { 'invalid' }

      it 'returns true' do
        expect(subject).to eq(true)
      end
    end

    context 'invalid primary key, invalid secondary key' do
      let(:primary_signature) { 'invalid' }
      let(:secondary_signature) { 'invalid' }

      it 'returns false' do
        expect(subject).to eq(false)
      end
    end

    context 'no signatures were supplied' do
      let(:primary_signature) { nil }
      let(:secondary_signature) { nil }

      it { is_expected.to eq(false) }
    end
  end

  describe '#valid_message?' do
    subject(:validate_message!) { validator.valid_message? }

    before do
      allow(validator).to receive(:verify_delivery_timestamp).and_return(true)
      allow(validator).to receive(:verify_signature).and_return(true)
    end

    it 'delegates to timestamp and signature verification' do
      expect(validator).to receive(:verify_delivery_timestamp).and_return(true)
      expect(validator).to receive(:verify_signature)

      expect(validate_message!).to eq(true)
    end
  end
end
