package io.mosip.idrepository.identity.repository;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

import io.mosip.idrepository.identity.entity.UinBiometricDraft;
import org.springframework.data.jpa.repository.Modifying;

/**
 * The Interface UinBiometricRepo.
 *
 * @author Manoj SP
 */
public interface UinBiometricDraftRepo extends JpaRepository<UinBiometricDraft, String> {

     @Modifying
     @Transactional
     void deleteByRegId(String regId);
}
