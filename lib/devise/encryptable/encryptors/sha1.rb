require "digest/sha1"

module Devise
  module Encryptable
    module Encryptors
      # = Sha1
      # Uses the Sha1 hash algorithm to encrypt passwords.
      class Sha1 < Base
        # Generates a default password digest based on stretches, salt, pepper and the
        # incoming password.
        def self.digest(password)
          digest = self.secure_digest(password)
          digest
        end

      private

        # Generate a SHA1 digest joining args. Generated token is something like
        #   --arg1--arg2--arg3--argN--
        def self.secure_digest(password)
          ::Digest::SHA1.hexdigest(password)
        end
      end
    end
  end
end
