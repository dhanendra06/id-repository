package io.mosip.idrepository.identity.repository;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

import io.mosip.idrepository.identity.entity.UinDocumentDraft;
import org.springframework.data.jpa.repository.Modifying;

/**
 * The Interface UinDocumentRepo.
 *
 * @author Manoj SP
 */
public interface UinDocumentDraftRepo extends JpaRepository<UinDocumentDraft, String> {

    @Modifying
    @Transactional
    void deleteByRegId(String regId);
}
